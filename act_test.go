package swarm_act

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/asabya/swarm-blockstore/bee"
	"github.com/asabya/swarm-blockstore/bee/mock"
	"github.com/ethersphere/bee/v2/pkg/accesscontrol"
	"github.com/ethersphere/bee/v2/pkg/accesscontrol/kvs"
	"github.com/ethersphere/bee/v2/pkg/crypto"
	"github.com/ethersphere/bee/v2/pkg/feeds/factory"
	"github.com/ethersphere/bee/v2/pkg/file"
	"github.com/ethersphere/bee/v2/pkg/file/loadsave"
	"github.com/ethersphere/bee/v2/pkg/file/pipeline"
	"github.com/ethersphere/bee/v2/pkg/file/pipeline/builder"
	"github.com/ethersphere/bee/v2/pkg/file/redundancy"
	mockpost "github.com/ethersphere/bee/v2/pkg/postage/mock"
	mockstorer "github.com/ethersphere/bee/v2/pkg/storer/mock"
	"github.com/ethersphere/bee/v2/pkg/swarm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestController_UpdateHandler(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	publisher := getPrivKey(0)
	diffieHellman := accesscontrol.NewDefaultSession(publisher)
	al := accesscontrol.NewLogic(diffieHellman)
	storer := mockstorer.New()
	beeUrl := mock.NewTestBeeServer(t, mock.TestServerOptions{
		Storer:          storer,
		PreventRedirect: true,
		Post:            mockpost.New(mockpost.WithAcceptAll()),
		Feeds:           factory.New(storer.Lookup()),
	})
	beeApi := bee.NewBeeClient(beeUrl, bee.WithRedundancy(fmt.Sprintf("%d", redundancy.NONE)), bee.WithStamp(mock.BatchOkStr))

	a := New(beeApi, publisher, mock.BatchOkStr)
	ls := loadsave.New(a.pg, a.pg, func() pipeline.Interface {
		return builder.NewPipelineBuilder(ctx, a.pg, false, redundancy.NONE)
	})
	href, err := getHistoryFixture(t, ctx, ls, al, &publisher.PublicKey)
	assertNoError(t, "history fixture create", err)

	grantee1 := getPrivKey(0)
	grantee := getPrivKey(2)

	_, _ = href, grantee1
	t.Run("add to new list", func(t *testing.T) {
		addList := []*ecdsa.PublicKey{&grantee.PublicKey}
		encodedAddList, err := encodeKeys(addList)
		require.NoError(t, err)
		resp, err := a.CreateGrantee(ctx, swarm.ZeroAddress, encodedAddList)
		require.NoError(t, err)

		gl, err := a.GetGrantees(ctx, resp.Reference)
		require.NoError(t, err)

		assertNoError(t, "create granteelist ref", err)
		assert.Len(t, gl, 1)
	})
	t.Run("add to existing list", func(t *testing.T) {
		addList := []*ecdsa.PublicKey{&grantee.PublicKey}
		encodedAddList, err := encodeKeys(addList)
		require.NoError(t, err)
		resp, err := a.CreateGrantee(ctx, swarm.ZeroAddress, encodedAddList)
		require.NoError(t, err)

		gl, err := a.GetGrantees(ctx, resp.Reference)
		require.NoError(t, err)

		assertNoError(t, "create granteelist ref", err)
		assert.Len(t, gl, 1)

		addList = []*ecdsa.PublicKey{&getPrivKey(0).PublicKey}
		encodedAddList, err = encodeKeys(addList)
		require.NoError(t, err)
		resp, err = a.RevokeGrant(ctx, resp.Reference, href, encodedAddList, nil)
		assertNoError(t, "UpdateHandler", err)
		gl, err = a.GetGrantees(ctx, resp.Reference)
		assertNoError(t, "create granteelist ref", err)
		assert.Len(t, gl, 2)
	})
	t.Run("add and revoke", func(t *testing.T) {
		addList := []*ecdsa.PublicKey{&grantee.PublicKey, &grantee1.PublicKey}
		encodedAddList, err := encodeKeys(addList)
		require.NoError(t, err)
		resp, err := a.CreateGrantee(ctx, swarm.ZeroAddress, encodedAddList)
		require.NoError(t, err)

		removeList := []*ecdsa.PublicKey{&grantee1.PublicKey}
		encodedRemoveList, err := encodeKeys(removeList)
		require.NoError(t, err)
		resp, err = a.RevokeGrant(ctx, resp.Reference, href, nil, encodedRemoveList)
		require.NoError(t, err)

		gl, err := a.GetGrantees(ctx, resp.Reference)
		assertNoError(t, "granteelist ref", err)
		assert.Len(t, gl, 1)

		grantees, err := encodeKeys([]*ecdsa.PublicKey{&grantee.PublicKey})
		assertNoError(t, "granteelist ref", err)
		assert.Equal(t, gl, grantees)
	})
	t.Run("add and revoke then get from history", func(t *testing.T) {
		addRevokeList := []*ecdsa.PublicKey{&grantee.PublicKey}
		encodedAddRevokeList, err := encodeKeys(addRevokeList)
		assertNoError(t, "granteelist ref", err)
		ref := swarm.RandAddress(t)
		res, err := a.HandleUpload(ctx, ref, swarm.ZeroAddress)
		require.NoError(t, err)

		// Need to wait a second before each update call so that a new history mantaray fork is created for the new key(timestamp) entry
		time.Sleep(1 * time.Second)
		beforeRevokeTS := time.Now().Unix()
		res1, err := a.CreateGrantee(ctx, res.HistoryReference, encodedAddRevokeList)
		require.NoError(t, err)

		time.Sleep(1 * time.Second)
		res2, err := a.RevokeGrant(ctx, res1.Reference, res1.HistoryReference, nil, encodedAddRevokeList)
		require.NoError(t, err)

		//gl, err := accesscontrol.NewGranteeListReference(ctx, ls, res2.Reference)
		//require.NoError(t, err)
		//assert.Empty(t, gl.Get())
		//// expect history reference to be different after grantee list update
		//assert.NotEqual(t, res1.HistoryReference, res2.HistoryReference)

		granteeDH := accesscontrol.NewDefaultSession(grantee)
		granteeAl := accesscontrol.NewLogic(granteeDH)
		granteeCtrl := accesscontrol.NewController(granteeAl)
		// download with grantee shall still work with the timestamp before the revoke
		decRef, err := granteeCtrl.DownloadHandler(ctx, ls, res.Reference, &publisher.PublicKey, res2.HistoryReference, beforeRevokeTS)
		require.NoError(t, err)
		assert.Equal(t, ref, decRef)

		// download with grantee shall NOT work with the latest timestamp
		decRef, err = granteeCtrl.DownloadHandler(ctx, ls, res2.Reference, &publisher.PublicKey, res2.HistoryReference, time.Now().Unix())
		require.Error(t, err)
		assert.Equal(t, swarm.ZeroAddress, decRef)

		// publisher shall still be able to download with the timestamp before the revoke
		decRef, err = a.HandleDownload(ctx, res.Reference, res2.HistoryReference, beforeRevokeTS)
		require.NoError(t, err)
		assert.Equal(t, ref, decRef)
	})
	//t.Run("add twice", func(t *testing.T) {
	//	addList := []*ecdsa.PublicKey{&grantee.PublicKey, &grantee.PublicKey}
	//	//nolint:ineffassign,staticcheck,wastedassign
	//	granteeRef, eglref, _, _, err := c.UpdateHandler(ctx, ls, gls, swarm.ZeroAddress, href, &publisher.PublicKey, addList, nil)
	//	granteeRef, _, _, _, err = c.UpdateHandler(ctx, ls, ls, eglref, href, &publisher.PublicKey, addList, nil)
	//	assertNoError(t, "UpdateHandler", err)
	//	gl, err := accesscontrol.NewGranteeListReference(ctx, ls, granteeRef)
	//
	//	assertNoError(t, "create granteelist ref", err)
	//	assert.Len(t, gl.Get(), 1)
	//})
	//t.Run("revoke non-existing", func(t *testing.T) {
	//	addList := []*ecdsa.PublicKey{&grantee.PublicKey}
	//	granteeRef, _, _, _, err := c.UpdateHandler(ctx, ls, ls, swarm.ZeroAddress, href, &publisher.PublicKey, addList, nil)
	//	assertNoError(t, "UpdateHandler", err)
	//	gl, err := accesscontrol.NewGranteeListReference(ctx, ls, granteeRef)
	//
	//	assertNoError(t, "create granteelist ref", err)
	//	assert.Len(t, gl.Get(), 1)
	//})
}

//nolint:errcheck,gosec,wrapcheck
func getHistoryFixture(t *testing.T, ctx context.Context, ls file.LoadSaver, al accesscontrol.ActLogic, publisher *ecdsa.PublicKey) (swarm.Address, error) {
	t.Helper()
	h, err := accesscontrol.NewHistory(ls)
	if err != nil {
		return swarm.ZeroAddress, err
	}
	pk1 := getPrivKey(1)
	pk2 := getPrivKey(2)

	kvs0, err := kvs.New(ls)
	assertNoError(t, "kvs0 create", err)
	al.AddGrantee(ctx, kvs0, publisher, publisher)
	kvs0Ref, err := kvs0.Save(ctx)
	assertNoError(t, "kvs0 save", err)
	kvs1, err := kvs.New(ls)
	assertNoError(t, "kvs1 create", err)
	al.AddGrantee(ctx, kvs1, publisher, publisher)
	al.AddGrantee(ctx, kvs1, publisher, &pk1.PublicKey)
	kvs1Ref, err := kvs1.Save(ctx)
	assertNoError(t, "kvs1 save", err)
	kvs2, err := kvs.New(ls)
	assertNoError(t, "kvs2 create", err)
	al.AddGrantee(ctx, kvs2, publisher, publisher)
	al.AddGrantee(ctx, kvs2, publisher, &pk2.PublicKey)
	kvs2Ref, err := kvs2.Save(ctx)
	assertNoError(t, "kvs2 save", err)
	firstTime := time.Date(1994, time.April, 1, 0, 0, 0, 0, time.UTC).Unix()
	secondTime := time.Date(2000, time.April, 1, 0, 0, 0, 0, time.UTC).Unix()
	thirdTime := time.Date(2015, time.April, 1, 0, 0, 0, 0, time.UTC).Unix()

	h.Add(ctx, kvs0Ref, &thirdTime, nil)
	h.Add(ctx, kvs1Ref, &firstTime, nil)
	h.Add(ctx, kvs2Ref, &secondTime, nil)
	return h.Store(ctx)
}

func assertNoError(t *testing.T, msg string, err error) {
	t.Helper()
	if err != nil {
		assert.FailNowf(t, err.Error(), msg)
	}
}

func getPrivKey(keyNumber int) *ecdsa.PrivateKey {
	var keyHex string

	switch keyNumber {
	case 0:
		keyHex = "a786dd84b61485de12146fd9c4c02d87e8fd95f0542765cb7fc3d2e428c0bcfa"
	case 1:
		keyHex = "b786dd84b61485de12146fd9c4c02d87e8fd95f0542765cb7fc3d2e428c0bcfb"
	case 2:
		keyHex = "c786dd84b61485de12146fd9c4c02d87e8fd95f0542765cb7fc3d2e428c0bcfc"
	default:
		panic("Invalid key number")
	}

	data, err := hex.DecodeString(keyHex)
	if err != nil {
		panic(err)
	}

	privKey, err := crypto.DecodeSecp256k1PrivateKey(data)
	if err != nil {
		panic(err)
	}

	return privKey
}

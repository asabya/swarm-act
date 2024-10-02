// Package swarm_act provides an integration of Swarm's Access Control Trie (ACT) for user-based access control.
// It enables initializing access control with a user's key and allows adding or revoking grantees at the user level.
package swarm_act

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"

	"github.com/asabya/swarm-act/pkg/blockstore"
	"github.com/asabya/swarm-act/pkg/blockstore/putergetter"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethersphere/bee/v2/pkg/accesscontrol"
	"github.com/ethersphere/bee/v2/pkg/api"
	"github.com/ethersphere/bee/v2/pkg/crypto"
	"github.com/ethersphere/bee/v2/pkg/file/loadsave"
	"github.com/ethersphere/bee/v2/pkg/file/pipeline"
	"github.com/ethersphere/bee/v2/pkg/file/pipeline/builder"
	"github.com/ethersphere/bee/v2/pkg/file/redundancy"
	"github.com/ethersphere/bee/v2/pkg/swarm"
)

// ACT represents the Access Control Trie integration for user-based access control.
// It encapsulates the access control controller, the user's public key, and the PutGetter client.
type ACT struct {
	publicKey  *ecdsa.PublicKey
	controller *accesscontrol.ControllerStruct
	pg         *putergetter.PutGetter
}

// New initializes a new ACT instance with the given user's private key, Bee client, and postage stamp ID.
func New(bee blockstore.Client, key *ecdsa.PrivateKey, stamp string) *ACT {
	pg, err := putergetter.NewPutGetter(bee, stamp, fmt.Sprintf("%d", redundancy.NONE), false)
	if err != nil {
		return nil
	}

	session := accesscontrol.NewDefaultSession(key)
	actLogic := accesscontrol.NewLogic(session)
	ac := accesscontrol.NewController(actLogic)
	return &ACT{
		controller: ac,
		pg:         pg,
		publicKey:  key.Public().(*ecdsa.PublicKey),
	}
}

// CreateGrantee adds new grantees to the access control list.
// It creates a new encrypted grantee list and updates the history reference.
func (a *ACT) CreateGrantee(ctx context.Context, historyAddress swarm.Address, granteeList []string) (*api.GranteesPostResponse, error) {
	list, err := parseKeys(granteeList)
	if err != nil {
		return nil, err
	}
	ls := loadsave.New(a.pg, a.pg, func() pipeline.Interface {
		return builder.NewPipelineBuilder(ctx, a.pg, false, redundancy.NONE)
	})
	gls := loadsave.New(a.pg, a.pg, func() pipeline.Interface {
		return builder.NewPipelineBuilder(ctx, a.pg, true, redundancy.NONE)
	})
	_, encryptedglref, historyref, _, err := a.controller.UpdateHandler(ctx, ls, gls, swarm.ZeroAddress, historyAddress, a.publicKey, list, nil)
	if err != nil {
		return nil, err
	}
	return &api.GranteesPostResponse{
		Reference:        encryptedglref,
		HistoryReference: historyref,
	}, nil
}

// GetGrantees retrieves the list of current grantees from the access control list.
func (a *ACT) GetGrantees(ctx context.Context, granteesAddress swarm.Address) ([]string, error) {
	ls := loadsave.NewReadonly(a.pg)
	grantees, err := a.controller.Get(ctx, ls, a.publicKey, granteesAddress)
	if err != nil {
		return nil, err
	}
	granteeSlice := make([]string, len(grantees))
	for i, grantee := range grantees {
		granteeSlice[i] = hex.EncodeToString(crypto.EncodeSecp256k1PublicKey(grantee))
	}
	return granteeSlice, nil
}

// RevokeGrant updates the access control list by adding new grantees and revoking specified grantees.
func (a *ACT) RevokeGrant(ctx context.Context, granteesAddress, historyAddress swarm.Address, granteeList, revokeList []string) (*api.GranteesPostResponse, error) {
	addList, err := parseKeys(granteeList)
	if err != nil {
		return nil, err
	}

	removeList, err := parseKeys(revokeList)
	if err != nil {
		return nil, err
	}

	ls := loadsave.New(a.pg, a.pg, func() pipeline.Interface {
		return builder.NewPipelineBuilder(ctx, a.pg, false, redundancy.NONE)
	})
	gls := loadsave.New(a.pg, a.pg, func() pipeline.Interface {
		return builder.NewPipelineBuilder(ctx, a.pg, true, redundancy.NONE)
	})
	_, encryptedglref, historyref, _, err := a.controller.UpdateHandler(ctx, ls, gls, granteesAddress, historyAddress, a.publicKey, addList, removeList)
	if err != nil {
		return nil, err
	}
	return &api.GranteesPostResponse{
		Reference:        encryptedglref,
		HistoryReference: historyref,
	}, nil
}

// HandleUpload processes the upload operation with access control.
// It updates the references to the data and history feed.
func (a *ACT) HandleUpload(ctx context.Context, reference, historyAddress swarm.Address) (*api.GranteesPostResponse, error) {
	ls := loadsave.New(a.pg, a.pg, func() pipeline.Interface {
		return builder.NewPipelineBuilder(ctx, a.pg, false, redundancy.NONE)
	})
	_, href, ref, err := a.controller.UploadHandler(ctx, ls, reference, a.publicKey, historyAddress)
	if err != nil {
		return nil, err
	}
	return &api.GranteesPostResponse{
		Reference:        ref,
		HistoryReference: href,
	}, nil
}

// HandleDownload processes the download operation with access control.
// It checks the user's permissions and returns the address of the data if access is granted.
func (a *ACT) HandleDownload(ctx context.Context, reference, historyAddress swarm.Address, ts int64) (swarm.Address, error) {
	ls := loadsave.NewReadonly(a.pg)
	return a.controller.DownloadHandler(ctx, ls, reference, a.publicKey, historyAddress, ts)
}

func parseKeys(list []string) ([]*ecdsa.PublicKey, error) {
	parsedList := make([]*ecdsa.PublicKey, 0, len(list))
	for _, g := range list {
		h, err := hex.DecodeString(g)
		if err != nil {
			return []*ecdsa.PublicKey{}, fmt.Errorf("failed to decode grantee: %w", err)
		}
		k, err := btcec.ParsePubKey(h)
		if err != nil {
			return []*ecdsa.PublicKey{}, fmt.Errorf("failed to parse grantee public key: %w", err)
		}
		parsedList = append(parsedList, k.ToECDSA())
	}

	return parsedList, nil
}

func encodeKeys(keys []*ecdsa.PublicKey) ([]string, error) {
	encodedList := make([]string, 0, len(keys))
	for _, key := range keys {
		if key == nil {
			return nil, fmt.Errorf("nil key found")
		}
		encoded := hex.EncodeToString(crypto.EncodeSecp256k1PublicKey(key))
		encodedList = append(encodedList, encoded)
	}
	return encodedList, nil
}

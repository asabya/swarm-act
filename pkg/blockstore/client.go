package blockstore

import (
	"context"
	"github.com/ethersphere/bee/v2/pkg/swarm"
)

// Client is the interface for block store
type Client interface {
	UploadChunk(tag uint32, ch swarm.Chunk, stamp, redundancyLevel string, pin bool) (address swarm.Address, err error)
	DownloadChunk(ctx context.Context, address swarm.Address) (chunk swarm.Chunk, err error)
	CreateTag(address swarm.Address) (uint32, error)
}

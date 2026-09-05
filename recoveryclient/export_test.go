package recoveryclient

import "net/http"

// NewClientWithTransportForTest lets a test answer the client's requests without a network.
// The redirect policy stays installed, so tests exercise it.
func NewClientWithTransportForTest(rt http.RoundTripper, o Options) *Client {
	c := NewClient(o)
	c.client.Transport = rt
	return c
}

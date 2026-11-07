package smb2

import (
	"fmt"
	"runtime/debug"
)

// runGuarded runs the request loop and turns a panic in any request handler
// into an ordinary connection error. The caller then tears the connection
// down as usual, so a single misbehaving client cannot crash the server.
func (c *conn) runGuarded() (err error) {
	defer func() {
		if r := recover(); r != nil {
			c.errorf("panic in request handler: %v\n%s", r, debug.Stack())
			err = fmt.Errorf("request handler panic: %v", r)
		}
	}()
	return c.Run()
}

// recoverConn is deferred at the top of a connection's helper goroutines.
// A panic there is logged and only shuts down that connection.
func (c *conn) recoverConn(where string) {
	if r := recover(); r != nil {
		c.errorf("panic in %s: %v\n%s", where, r, debug.Stack())
		c.shutdown()
	}
}

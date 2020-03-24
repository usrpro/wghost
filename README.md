## Development

### Protocol buffers

The `wghost` API server uses gRPC through protocol buffers generation. To regenerate the gRPC definitions, run:

````
protoc --go_out=plugins=grpc:. wghost.proto
````
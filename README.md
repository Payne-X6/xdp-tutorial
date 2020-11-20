# Usage

## Compile

```
$ cd xdp-tutorial
$ make
```

## Load Filter

```
$ cd xdp-tutorial/packet-route
# ./xdp_loader -d <inet> -F --progsec xdp_packet_router [--auto-mode]
```

## Collect stats

```
$ cd xdp-tutorial/packet-route
# ./xdp_stats -d <inet> [-d <inet>]
```
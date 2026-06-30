# yip-bench Results

Generated: 2026-06-30 19:51:19 UTC

## yip vs kernel WireGuard — netem loss sweep
ping -c 100 -i 0.05 -W 1 across each tunnel; netem: loss X% delay 5ms (symmetric)

| injected% | yip_loss% | wg_loss%  | yip_rtt_ms | wg_rtt_ms |
|-----------|-----------|-----------|------------|-----------|
| 0%        | 0%         | 0%         | 10.541      | 10.322     |
| 1%        | 0%         | 2%         | 10.567      | 10.332     |
| 3%        | 0%         | 4%         | 10.544      | 10.360     |
| 5%        | 0%         | 8%         | 10.550      | 10.388     |
| 10%        | 1%         | 17%         | 10.544      | 10.337     |

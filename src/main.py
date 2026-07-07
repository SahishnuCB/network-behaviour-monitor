import json


def load_packets(file_path):
    with open(file_path, "r") as file:
        packets = json.load(file)
    return packets


def create_flow_key(packet):
    return (
        packet["src_ip"],
        packet["dst_ip"],
        packet["protocol"],
        packet["src_port"],
        packet["dst_port"],
    )


def get_service_name(port):
    common_ports = {
        21: "FTP",
        22: "SSH",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        5432: "PostgreSQL",
    }

    return common_ports.get(port, "Unknown")


def group_packets_into_flows(packets):
    flows = {}

    for packet in packets:
        flow_key = create_flow_key(packet)

        if flow_key not in flows:
            flows[flow_key] = {
                "src_ip": packet["src_ip"],
                "dst_ip": packet["dst_ip"],
                "protocol": packet["protocol"],
                "src_port": packet["src_port"],
                "dst_port": packet["dst_port"],
                "service": get_service_name(packet["dst_port"]),
                "packet_count": 0,
                "total_size": 0,
            }

        flows[flow_key]["packet_count"] += 1
        flows[flow_key]["total_size"] += packet["size"]

    return list(flows.values())


def build_baseline(flows):
    baseline = {
        "known_src_ips": set(),
        "known_dst_ips": set(),
        "known_dst_ports": set(),
        "known_protocols": set(),
        "known_services": set(),
    }

    for flow in flows:
        baseline["known_src_ips"].add(flow["src_ip"])
        baseline["known_dst_ips"].add(flow["dst_ip"])
        baseline["known_dst_ports"].add(flow["dst_port"])
        baseline["known_protocols"].add(flow["protocol"])
        baseline["known_services"].add(flow["service"])

    return baseline


def detect_anomalies(flows, baseline):
    alerts = []

    for flow in flows:
        if flow["dst_ip"] not in baseline["known_dst_ips"]:
            alerts.append(
                {
                    "type": "New Destination IP",
                    "flow": flow,
                    "reason": f'Destination IP {flow["dst_ip"]} was not seen in the baseline.',
                }
            )

        if flow["dst_port"] not in baseline["known_dst_ports"]:
            alerts.append(
                {
                    "type": "New Destination Port",
                    "flow": flow,
                    "reason": f'Destination port {flow["dst_port"]} was not seen in the baseline.',
                }
            )

    return alerts


def print_flows(flows, title="Network Flows"):
    print(f"\n{title}")
    print("-" * 80)

    for flow in flows:
        print(
            f'{flow["src_ip"]}:{flow["src_port"]} -> '
            f'{flow["dst_ip"]}:{flow["dst_port"]} '
            f'({flow["protocol"]}) | '
            f'Service: {flow["service"]} | '
            f'Packets: {flow["packet_count"]} | '
            f'Total Size: {flow["total_size"]} bytes'
        )


def print_alerts(alerts):
    print("\nAlerts")
    print("-" * 80)

    if not alerts:
        print("No unusual activity detected.")
        return

    for alert in alerts:
        flow = alert["flow"]

        print(f'Type: {alert["type"]}')
        print(f'Reason: {alert["reason"]}')
        print(
            f'Flow: {flow["src_ip"]}:{flow["src_port"]} -> '
            f'{flow["dst_ip"]}:{flow["dst_port"]} '
            f'({flow["protocol"]}) | Service: {flow["service"]}'
        )
        print("-" * 80)


def format_set(values):
    return ", ".join(str(value) for value in sorted(values))


def print_baseline(baseline):
    print("\nBaseline Profile")
    print("-" * 80)
    print(f'Known Source IPs: {format_set(baseline["known_src_ips"])}')
    print(f'Known Destination IPs: {format_set(baseline["known_dst_ips"])}')
    print(f'Known Destination Ports: {format_set(baseline["known_dst_ports"])}')
    print(f'Known Protocols: {format_set(baseline["known_protocols"])}')
    print(f'Known Services: {format_set(baseline["known_services"])}')


def main():
    baseline_packets = load_packets("data/sample_packets.json")
    baseline_flows = group_packets_into_flows(baseline_packets)
    baseline = build_baseline(baseline_flows)

    test_packets = load_packets("data/test_packets.json")
    test_flows = group_packets_into_flows(test_packets)
    alerts = detect_anomalies(test_flows, baseline)

    print_flows(baseline_flows, "Baseline Traffic Flows")
    print_baseline(baseline)
    print_flows(test_flows, "Test Traffic Flows")
    print_alerts(alerts)


if __name__ == "__main__":
    main()

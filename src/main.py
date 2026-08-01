import json
from datetime import datetime
import socket
import ipaddress

BASELINE_FILE = "data/baseline_packets.json"
TEST_FILE = "data/captured_packets.json"
OUTPUT_FILE = "data/analysis_result.json"

LARGE_TRANSFER_THRESHOLD = 1_000_000
HIGH_PACKET_COUNT_THRESHOLD = 1000


def get_local_ip():
    connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        connection.connect(("8.8.8.8", 80))
        return connection.getsockname()[0]
    finally:
        connection.close()


def load_packets(file_path):
    try:
        with open(file_path, "r") as file:
            packets = json.load(file)

        if not isinstance(packets, list):
            raise ValueError("Packet file must contain a JSON list.")

        if not packets:
            raise ValueError(f"{file_path} contains no packets.")

        return packets

    except FileNotFoundError:
        print(f"Error: Could not find {file_path}.")
        return None

    except json.JSONDecodeError:
        print(f"Error: {file_path} contains invalid JSON.")
        return None

    except ValueError as error:
        print(f"Error: {error}")
        return None


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
        25: "SMTP",
        53: "DNS",
        67: "DHCP Server",
        68: "DHCP Client",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram Service",
        143: "IMAP",
        443: "HTTPS",
        990: "FTPS",
        993: "IMAPS",
        995: "POP3S",
        1900: "SSDP",
        3306: "MySQL",
        5353: "mDNS",
        5355: "LLMNR",
        5432: "PostgreSQL",
        8883: "MQTT over TLS",
        9200: "Elasticsearch",
        27015: "Game Server",
        27017: "MongoDB",
    }

    return common_ports.get(port, "Unknown")


def group_packets_into_flows(packets):
    flows = {}

    required_fields = {
        "src_ip",
        "dst_ip",
        "protocol",
        "src_port",
        "dst_port",
        "size",
    }

    for packet in packets:
        if not isinstance(packet, dict):
            print("Warning: Skipping invalid packet entry.")
            continue

        if not required_fields.issubset(packet):
            print(f"Warning: Skipping packet with missing fields: {packet}")
            continue

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


def is_normal_local_service(flow):
    normal_local_services = {
        "DHCP Server",
        "DHCP Client",
        "NetBIOS Name Service",
        "NetBIOS Datagram Service",
        "SSDP",
        "mDNS",
        "LLMNR",
    }

    return flow["service"] in normal_local_services


def is_private_ip(ip_address):
    try:
        return ipaddress.ip_address(ip_address).is_private
    except ValueError:
        return False


def detect_anomalies(flows, baseline):
    alerts = []

    for flow in flows:
        reasons = []
        risk_score = 0
        new_destination_ip = flow["dst_ip"] not in baseline["known_dst_ips"]

        if is_normal_local_service(flow):
            continue

        if flow["protocol"] not in baseline["known_protocols"]:
            reasons.append(f'Protocol {flow["protocol"]} was not seen in the baseline.')
            risk_score += 2

        if flow["protocol"] in {"TCP", "UDP"}:
            if flow["dst_port"] not in baseline["known_dst_ports"]:
                if flow["service"] == "Unknown":
                    reasons.append(
                        f'Destination port {flow["dst_port"]} was not seen in the '
                        "baseline and is not mapped to a common service."
                    )
                    risk_score += 2
                else:
                    reasons.append(
                        f'Destination port {flow["dst_port"]} was not seen in the '
                        f'baseline, but it is commonly used for {flow["service"]}.'
                    )
                    risk_score += 1

            if flow["service"] == "Unknown":
                reasons.append(
                    f'Service for destination port {flow["dst_port"]} is unknown.'
                )
                risk_score += 1

        if flow["total_size"] > LARGE_TRANSFER_THRESHOLD:
            reasons.append(
                f'Total size of {flow["total_size"]} bytes exceeds the threshold of {LARGE_TRANSFER_THRESHOLD} bytes.'
            )
            risk_score += 2

        if flow["packet_count"] > HIGH_PACKET_COUNT_THRESHOLD:
            reasons.append(
                f'Packet count of {flow["packet_count"]} exceeds the threshold of {HIGH_PACKET_COUNT_THRESHOLD} packets.'
            )
            risk_score += 2

        if new_destination_ip and risk_score > 0:
            if is_private_ip(flow["dst_ip"]):
                reasons.insert(
                    0,
                    f'Destination IP {flow["dst_ip"]} is a new private IP address not seen in the baseline.'
                )
            else:
                reasons.insert(
                    0,
                    f'Destination IP {flow["dst_ip"]} is a new public IP address not seen in the baseline.'
                )

            risk_score += 1

        if reasons:
            alerts.append(
                {
                    "type": "Suspicious Flow",
                    "flow": flow,
                    "risk_score": risk_score,
                    "risk_level": get_risk_level(risk_score),
                    "reasons": reasons,
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


def get_risk_level(risk_score):
    if risk_score >= 5:
        return "High"
    elif risk_score >= 3:
        return "Medium"
    else:
        return "Low"


def print_alerts(alerts):
    print("\nAlerts")
    print("-" * 80)

    if not alerts:
        print("No unusual activity detected.")
        return

    for alert in alerts:
        flow = alert["flow"]

        print(f'Type: {alert["type"]}')
        print(f'Risk Score: {alert["risk_score"]}')
        print(f'Risk Level: {alert["risk_level"]}')
        print(
            f'Flow: {flow["src_ip"]}:{flow["src_port"]} -> '
            f'{flow["dst_ip"]}:{flow["dst_port"]} '
            f'({flow["protocol"]}) | Service: {flow["service"]}'
        )

        print("Reasons:")
        for reason in alert["reasons"]:
            print(f"- {reason}")

        print("-" * 80)


def get_top_talkers(flows):
    destination_totals = {}

    for flow in flows:
        dst_ip = flow["dst_ip"]

        if dst_ip not in destination_totals:
            destination_totals[dst_ip] = 0

        destination_totals[dst_ip] += flow["total_size"]

    top_talkers = sorted(
        destination_totals.items(), key=lambda item: item[1], reverse=True
    )

    return [
        {"dst_ip": dst_ip, "total_size": total_size} for dst_ip, total_size in top_talkers
    ]


def get_protocol_distribution(flows):
    protocol_counts = {}

    for flow in flows:
        protocol = flow["protocol"]

        if protocol not in protocol_counts:
            protocol_counts[protocol] = 0

        protocol_counts[protocol] += 1

    return protocol_counts


def save_analysis_result(file_path, baseline_flows, baseline, test_flows, alerts, top_talkers, protocol_distribution):
    result = {
        "generated_at": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        "baseline_flows": baseline_flows,
        "baseline_profile": {
            "known_src_ips": list(baseline["known_src_ips"]),
            "known_dst_ips": list(baseline["known_dst_ips"]),
            "known_dst_ports": list(baseline["known_dst_ports"]),
            "known_protocols": list(baseline["known_protocols"]),
            "known_services": list(baseline["known_services"]),
        },
        "test_flows": test_flows,
        "alerts": alerts,
        "top_talkers": top_talkers,
        "protocol_distribution": protocol_distribution
    }

    with open(file_path, "w") as file:
        json.dump(result, file, indent=4)


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


def print_summary(baseline_flows, test_flows, alerts):
    low = 0
    medium = 0
    high = 0

    for alert in alerts:
        if alert["risk_level"] == "Low":
            low += 1
        elif alert["risk_level"] == "Medium":
            medium += 1
        elif alert["risk_level"] == "High":
            high += 1

    print("\nAnalysis Summary")
    print("-" * 80)
    print(f"Baseline Flows : {len(baseline_flows)}")
    print(f"Test Flows     : {len(test_flows)}")
    print(f"Alerts         : {len(alerts)}")
    print(f"Low Risk       : {low}")
    print(f"Medium Risk    : {medium}")
    print(f"High Risk      : {high}")


def main():
    local_ip = get_local_ip()
    print(f"Local IP Address: {local_ip}")

    baseline_packets = load_packets(BASELINE_FILE)

    if baseline_packets is None:
        return

    all_baseline_flows = group_packets_into_flows(baseline_packets)

    baseline_flows = [flow for flow in all_baseline_flows if flow["src_ip"] == local_ip]

    if not baseline_flows:
        print("Error: No baseline flows found for the local IP address.")
        return

    baseline = build_baseline(baseline_flows)

    test_packets = load_packets(TEST_FILE)
    if test_packets is None:
        return

    all_test_flows = group_packets_into_flows(test_packets)

    test_flows = [flow for flow in all_test_flows if flow["src_ip"] == local_ip]

    alerts = detect_anomalies(test_flows, baseline)
    top_talkers = get_top_talkers(test_flows)
    protocol_distribution = get_protocol_distribution(test_flows)

    print_flows(baseline_flows, "Baseline Traffic Flows")
    print_baseline(baseline)
    print_flows(test_flows, "Test Traffic Flows")
    print_alerts(alerts)
    print_summary(baseline_flows, test_flows, alerts)

    save_analysis_result(
        OUTPUT_FILE,
        baseline_flows,
        baseline,
        test_flows,
        alerts,
        top_talkers,
        protocol_distribution,
    )


if __name__ == "__main__":
    main()

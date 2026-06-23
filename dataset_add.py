import pandas as pd
import random

# Set seed for reproducibility
SEED = 42
random.seed(SEED)

# Load your dataset
df = pd.read_csv(
    "D:/Intensive Period/Review_IEEE_IoT/CIC_IoMT_2024_WiFi_MQTT_test.csv")

# Define the severity scores based on the attack class
severity_scores = {
    "TCP_IP-DDoS-ICMP1_test": 10,
    "TCP_IP-DDoS-ICMP2_test": 10,
    "MQTT-DDoS-Connect_Flood_test": 9,
    "MQTT-DDoS-Publish_Flood_test": 9,
    "TCP_IP-DDoS-TCP_test": 9,
    "TCP_IP-DDoS-SYN_test": 9,
    "TCP_IP-DDoS-UDP1_test": 9,
    "TCP_IP-DDoS-UDP2_test": 9,
    "MQTT-DoS-Connect_Flood_test": 8,
    "MQTT-DoS-Publish_Flood_test": 8,
    "ARP_Spoofing_test": 7,
    "TCP_IP-DoS-ICMP_test": 7,
    "TCP_IP-DoS-SYN_test": 7,
    "TCP_IP-DoS-UDP_test": 7,
    "TCP_IP-DoS-TCP_test": 7,
    "Recon-VulScan_test": 6,
    "MQTT-Malformed_Data_test": 6,
    "Recon-OS_Scan_test": 5,
    "Recon-Port_Scan_test": 5,
    "Recon-Ping_Sweep_test": 4,
    "Benign_test": 0
}

# Default net_class=None → randomly picks 'A', 'B', or 'C' per call
# Explicit value ('A', 'B', 'C') → generates only that class
def generate_ip(net_class=None):
    if net_class is None:
        net_class = random.choice(['A', 'B', 'C'])

    if net_class == 'A':
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    elif net_class == 'B':
        return f"172.16.{random.randint(0, 255)}.{random.randint(0, 255)}"
    else:  # Class C
        return f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"

# Mapping severity scores
df['Severity_Score'] = df['label'].map(severity_scores)

# Assigning IP addresses
# - No argument → random class per row (default behavior)
# - Pass net_class='A'/'B'/'C' explicitly for Sensitivity Analysis runs
df['Source_IP'] = df['label'].apply(lambda x: generate_ip())
df['Destination_IP'] = df['label'].apply(lambda x: generate_ip())

# Save the updated dataframe
df.to_csv(
    'D:/Intensive Period/Review_IEEE_IoT/updated_dataset_with_ips.csv', index=False)

print("Dataset successfully updated with Severity Scores and Synthetic IPs.")
print(df[['label', 'Severity_Score', 'Source_IP', 'Destination_IP']].head(10))

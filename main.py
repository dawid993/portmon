import queue
import sqlite3
import threading
import time
from scapy.all import sniff, TCP, IP

traffic_queue = queue.Queue()
max_elements_per_session = 2**16
analyze_thread_int = 20
db_filename = "portmon.db"
db_table_name = "syn_packets"


def handle_packet(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        packet_tcp = packet[TCP]
        packet_ip = packet[IP]
        try:
            traffic_queue.put_nowait(
                (time.time(), packet_ip.src, packet_ip.dst, packet_tcp.dport)
            )
        except queue.Full:
            print("Queue is full. Cannot add new traffic packet")


def analyze_packets():
    analyze_connection = sqlite3.connect(db_filename)

    while True:
        elems_count = 0
        packets = []
        while elems_count < max_elements_per_session:
            try:
                packets.append(traffic_queue.get_nowait())
            except queue.Empty:
                print("Queue is empty")
                break

            elems_count += 1

        save(packets, analyze_connection)
        analyze_traffic_from_db(analyze_connection)
        time.sleep(analyze_thread_int)


def save(rows, connection):
    if len(rows) != 0:
        cursor = connection.cursor()
        cursor.executemany(
            f"""
            INSERT INTO {db_table_name} (timestamp, src_ip, dst_ip, dst_port) VALUES(?, ?, ?, ?)            
        """,
            rows,
        )

        connection.commit()


def analyze_traffic_from_db(connection):
    burst_records = fetch_from_db(connection, 5 * 60, 10)
    complementary_records = fetch_from_db(connection, 24 * 60 * 60, 20)
    
    print(burst_records)
    print(complementary_records)


def fetch_from_db(connection, cutoff, port_threshold):
    cursor = connection.cursor()

    cursor.execute(
        f"""
        SELECT src_ip,
            COUNT(DISTINCT dst_port) as unique_ports
        FROM syn_packets
        WHERE timestamp > ?
        GROUP BY src_ip
        HAVING unique_ports > ?
    """,
        (time.time() - cutoff, port_threshold),
    )

    return cursor.fetchall()


def init_db():
    connection = sqlite3.connect(db_filename)
    cursor = connection.cursor()

    cursor.execute("PRAGMA journal_mode=WAL;")

    cursor.execute(
        f"""
        SELECT name FROM sqlite_master 
        WHERE type = 'table' AND name='{db_table_name}'
        LIMIT 1         
        """
    )

    # Create table if it doesn't exist
    if cursor.fetchone() is None:
        cursor.execute(
            f"""
            CREATE TABLE {db_table_name} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                timestamp REAL
            )
            """
        )

    connection.commit()
    connection.close()


def main():
    init_db()
    analysis_thread = threading.Thread(target=analyze_packets, daemon=True)
    analysis_thread.start()
    sniff(iface="wlo1", filter="tcp", prn=handle_packet)


if __name__ == "__main__":
    main()

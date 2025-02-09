#!./.venv/bin/python

import click
import threading
import json
from pydantic import ValidationError
from scapy.all import conf
from scapy_cip_enip.cip import CIP, CIP_Path
import time

from scapy_cip_enip.enip_tcp import ENIP_SendUnitData

from class1 import craft_class1_32bitheader_packet
from class3 import gen_class_3_cip_packet, randomize_service
from class0 import craft_class0_32_bit_header_packet, craft_class0_modeless_packet
from cli_types import Class0, Class1, Class3, MainModel
from tcp import connect_to_plc
from utils import random_interval_between, random_application_data

"""
Add a verbose flag to print the packet response on the CLI itself.
TODO: Add verbose logging
"""


def generate_class0_traffic(cfg, verbose, src_ip, stop_event, session_duration):
    """
    :param cfg: Configuration object containing destination IP, port, and requested packet interval (RPI).
    :type cfg: object
    :param verbose: Flag to enable verbose output.
    :type verbose: bool
    :param src_ip: Source IP address from where the traffic is generated.
    :type src_ip: str
    :param stop_event: Event object used to signal the termination of the traffic generation loop.
    :type stop_event: threading.Event
    :param session_duration: Duration of the session in minutes for which the traffic should be generated.
    :type session_duration: int
    :return: None
    """
    client = None
    try:
        client = connect_to_plc(str(cfg.dst_ip), str(cfg.dst_port))
        click.echo(f"Generating Class0 traffic from {src_ip} to {cfg.dst_ip}")
        packet_count = {
            'success': 0,
            'failure': 0
        }
        start_time = time.time()
        session_duration_seconds = session_duration * 60
        while not stop_event.is_set() and (time.time() - start_time) < session_duration_seconds and client is not None:
            try:

                pkt = craft_class0_modeless_packet(str(src_ip), str(cfg.dst_ip), random_application_data(8, 60))
                client.send_cip_udp(pkt)
                packet_count['success'] += 1
                print(".", end="", flush=True)
            except Exception as e:
                # no need to give a lot of info
                packet_count['failure'] += 1
                print("x", end="", flush=True)
            time.sleep(cfg.rpi / 1000.0)
        click.echo(
            f"\n\nTotal Class0 packets sent: {packet_count['success'] + packet_count['failure']} | failed: {packet_count['failure']} | success: {packet_count['success']} | failure: {packet_count['failure']}")
        client.sock.close()  # close the connection
    except Exception as e:
        click.echo(f"{e}")
        if client is not None:
            client.sock.close()  # close the connection
        stop_event.set()



def generate_class1_traffic(cfg, verbose, src_ip, stop_event, session_duration):
    """
    :param cfg: Configuration object containing destination IP, port, and RPI (Requested Packet Interval).
    :param verbose: Boolean flag to enable or disable detailed logging.
    :param src_ip: Source IP address for generating Class1 traffic.
    :param stop_event: Thread-safe event object to signal the process to stop.
    :param session_duration: Duration of the traffic generation session in minutes.
    :return: None
    """
    client = None
    try:
        client = connect_to_plc(str(cfg.dst_ip), str(cfg.dst_port))
        click.echo(f"Generating Class1 traffic from {src_ip} to {cfg.dst_ip} with rpi {cfg.rpi}")
        packet_count = {
            'success': 0,
            'failure': 0
        }
        start_time = time.time()
        session_duration_seconds = session_duration * 60
        while not stop_event.is_set() and (time.time() - start_time) < session_duration_seconds and client is not None:
            try:
                pkt = craft_class1_32bitheader_packet(src_ip, cfg.dst_ip, random_application_data(8,60))
                client.send_cip_udp(pkt)
                packet_count['success'] += 1
                print(".", end="", flush=True)
            except Exception as e:
                # no need to stop the main thread, we just record the failures
                packet_count['failure'] += 1
                print("x", end="", flush=True)
            time.sleep(cfg.rpi / 1000.0)
        print(
            f"\n\nTotal Class1 packets sent: {packet_count['success'] + packet_count['failure']} | failed: {packet_count['failure']} | success: {packet_count['success']} | failure: {packet_count['failure']}")
        if client is not None:
            client.sock.close()  # close the connection
    except Exception as e:
            click.echo(f"{e}")
            if client is not None:
                client.sock.close()  # close the connection
            stop_event.set()


def generate_class3_traffic(cfg, verbose, src_ip, stop_event, session_duration):
    """
    :param cfg: Configuration object containing destination IP, destination port, and random interval settings.
    :type cfg: object
    :param verbose: Flag to enable or disable verbose output.
    :type verbose: bool
    :param src_ip: Source IP address from which the traffic will be generated.
    :type src_ip: str
    :param stop_event: Event object used to signal when to stop generating traffic.
    :type stop_event: threading.Event
    :param session_duration: Duration of the traffic generation session in minutes.
    :type session_duration: int
    :return: None
    """
    client = None
    try:
        client = connect_to_plc(str(cfg.dst_ip), str(cfg.dst_port))
        packet_count = {
            'total': 0,
            'success': 0,
            'failure': 0
        }
        sport = client.sock.getsockname()[1]
        click.echo(
            f"Generating Class3 traffic from {src_ip}:{sport} to {cfg.dst_ip}:{cfg.dst_port} with rpi none")
        kwargs = {
            "src_ip": str(src_ip),
            "dst_ip": str(cfg.dst_ip),
            "dport": int(cfg.dst_port),
            "service": randomize_service()
        }
        start_time = time.time()
        session_duration_seconds = session_duration * 60
        while not stop_event.is_set() and (time.time() - start_time) < session_duration_seconds and client is not None:
            try:
                flag = "S" if packet_count['total'] == 1 else "PA" # only s if it is the first packet
                pkt = gen_class_3_cip_packet(str(src_ip), str(cfg.dst_ip), dport=cfg.dst_port,
                                       sport=sport, service=0x4c, path=CIP_Path.make(class_id=0x93, instance_id=3, member_id=None, attribute_id=10), seq=packet_count['success'], flag=flag)
                client.sock.send(bytes(pkt[ENIP_SendUnitData]))
                packet_count['success'] += 1
                print(".", end="", flush=True)
            except Exception as e:
                print(e)
                packet_count['failure'] += 1
                print("x", end="", flush=True)
            time.sleep(random_interval_between(cfg.min_random, cfg.max_random))
        print(
            f"\n\nTotal Class3  packets sent: {packet_count['success'] + packet_count['failure']} | failed: {packet_count['failure']} | success: {packet_count['success']} | failure: {packet_count['failure']}")
        if client is not None:
            client.sock.close()  # close the connection
    except Exception as e:
        click.echo(f"{e}")
        if client is not None:
            client.sock.close()  # close the connection
        stop_event.set()



    if verbose:
        pass


# Interactive mode command
@click.command()
@click.pass_context
def interactive(ctx):
    """
    :param ctx: Click context object that holds necessary parameters passed during the command execution, notably session duration and verbosity settings.
    :return: None

    This function runs an interactive session to configure and generate specific types of network traffic (class 0, class 1, or class 3).
    The user is prompted to input session duration and choose the traffic class type (0, 1, or 3). Further parameters required for the traffic type are requested interactively.

    For each traffic class:
    - Class 0: Accepts destination IP, destination port, and RPI (Random Packet Interval).
    - Class 1: Accepts destination IP, destination port, and RPI.
    - Class 3: Accepts destination IP, destination port, minimum random interval, and maximum random interval.

    After gathering inputs, the function validates them against the respective class schema. If the validation is successful, it initializes a thread to generate the traffic of the selected class.
    The thread listens for a stop event and can gracefully terminate on user interruption (CTRL+C) or when the stop event is explicitly triggered.
    """
    verbose = ctx.obj.get('VERBOSE', False)
    valid_classes = ['0', '1', '3']
    class_choice = None
    session_duration = click.prompt('How long do you want to keep the session alive? (in minutes)', type=int)
    ctx.obj['session_duration'] = session_duration # add session_duration to context

    while class_choice not in valid_classes:
        class_input = click.prompt('Select the type of traffic (class 0, class 1, class 3) [Enter the class number (0/1/3) or (class 0/class 1/class 3)]', type=str)
        if class_input.strip().lower() in ['class 0', '0']:
            class_choice = '0'
        elif class_input.strip().lower() in ['class 1', '1']:
            class_choice = '1'
        elif class_input.strip().lower() in ['class 3', '3']:
            class_choice = '3'
        else:
            click.echo("Invalid choice. Please select from 'class 0', 'class 1', 'class 3'.")


    # initialize a thread to None
    t = None
    stop_event = threading.Event()

    if class_choice == '0':
        # Prompt for src_ip and dst_ip
        dst_ip = click.prompt('Enter dst_ip', type=str)
        dst_port = click.prompt('Enter dst_port', type=int)
        rpi = click.prompt('Enter rpi', type=int)

        # Validate IP addresses
        try:
            data = {'dst_ip': dst_ip, 'dst_port': dst_port, 'rpi': rpi}
            class0_obj = Class0(**data)
        except ValidationError as e:
            click.echo(f"Invalid input:\n{e}")
            return
        # Generate traffic
        t = threading.Thread(target=generate_class0_traffic, args=(class0_obj, verbose, ctx.obj.get('src_ip'), stop_event, session_duration))
        t.start()
        try:
            while t.is_alive():
                if stop_event.is_set():
                    print("Stop event received. Exiting main thread...")
                    break
                time.sleep(1)  # Avoid busy waiting
        except KeyboardInterrupt:
            print("KeyboardInterrupt detected. Stopping thread...")
            stop_event.set()


    elif class_choice == '1':
        # Prompt for src_ip, dst_ip, rpi
        dst_ip = click.prompt('Enter dst_ip', type=str)
        dst_port = click.prompt('Enter port', type=int)
        rpi = click.prompt('Enter rpi', type=int)
        # Validate inputs
        try:
            data = {'dst_ip': dst_ip, 'dst_port': dst_port, 'rpi': rpi}
            class1_obj = Class1(**data)
        except ValidationError as e:
            click.echo(f"Invalid input:\n{e}")
            return
        # Generate traffic
        t = threading.Thread(target=generate_class1_traffic, args=(class1_obj, verbose, ctx.obj.get('src_ip'), stop_event, session_duration))
        t.start()
        # stop the thread, send a stop event
        try:
            while t.is_alive():
                if stop_event.is_set():
                    print("\nStop event received. Exiting main thread...")
                    break
                time.sleep(1)  # Avoid busy waiting
        except KeyboardInterrupt:
            print("\nKeyboardInterrupt detected. Stopping thread...")
            stop_event.set()


    elif class_choice == '3':
        # Prompt for src_ip, dst_ip, source_port, dest_port, rpi
        dst_ip = click.prompt('Enter dst_ip', type=str)
        dest_port = click.prompt('Enter dest_port', type=int)
        min_random = click.prompt('Enter min time (in seconds)', type=int)
        max_random = click.prompt('Enter max time  (in seconds)', type=int)
        # Validate inputs
        try:
            data = {
                'dst_ip': dst_ip,
                'dst_port': dest_port,
                'min_random': min_random,
                'max_random': max_random,
            }
            class3_obj = Class3(**data)
        except ValidationError as e:
            click.echo(f"Invalid input:\n{e}")
            return
        # Generate traffic
        t = threading.Thread(target=generate_class3_traffic, args=(class3_obj, ctx.obj.get('src_ip'), verbose, stop_event, session_duration))
        t.start()
        # stop the thread, send a stop event
        try:
            while t.is_alive():
                if stop_event.is_set():
                    print("Stop event received. Exiting main thread...")
                    break
                time.sleep(1)  # Avoid busy waiting
        except KeyboardInterrupt:
            print("KeyboardInterrupt detected. Stopping thread...")
            stop_event.set()

    try:
        t.join()
    except KeyboardInterrupt:
        click.echo("Generation stopped by user!")


# Concurrent mode command
@click.command()
@click.option('--config', type=click.Path(exists=True), required=True, help='Path to JSON config file.')
@click.option("--session_duration", type=int, help="Session duration in minutes.", required=True)
@click.pass_context
def concurrent(ctx, config,session_duration):
    """
    Handle concurrent execution of traffic generation for multiple classes based on provided configurations.

    :param ctx: Click context object containing command-line state and options.
    :param config: Path to the JSON configuration file specifying the setup for traffic generation.
    :param session_duration: Session duration in minutes for how long the traffic generation threads should run.
    :return: None
    """
    verbose = ctx.obj.get('VERBOSE', False)

    ctx.obj['session_duration'] = session_duration
    with open(config, 'r') as f:
        json_data = f.read()

    # Validate the JSON
    try:
        data = json.loads(json_data)
        validated_data = MainModel(**data)
    except ValidationError as ve:
        click.echo("Invalid JSON:")
        click.echo(ve)
        return
    except json.JSONDecodeError as je:
        click.echo("Invalid JSON format:")
        click.echo(je)
        return

    threads = []
    stop_event = threading.Event()
    # Process class0 configurations
    if validated_data.class0:
        class0_configs = validated_data.class0
        if not isinstance(class0_configs, list):
            class0_configs = [class0_configs]
        for cfg in class0_configs:
            # TODO: Run this thread for session_duration time
            t = threading.Thread(target=generate_class0_traffic, args=(cfg, verbose, ctx.obj.get('src_ip'), stop_event, session_duration))
            threads.append(t)
            t.start()

    # Process class1 configurations
    if validated_data.class1:
        class1_configs = validated_data.class1
        if not isinstance(class1_configs, list):
            class1_configs = [class1_configs]
        for cfg in class1_configs:
            # TODO: Run this thread for session_duration time
            t = threading.Thread(target=generate_class1_traffic, args=(cfg, verbose, ctx.obj.get('src_ip'), stop_event, session_duration))
            threads.append(t)
            t.start()

    # Process class3 configurations
    if validated_data.class3:
        class3_configs = validated_data.class3
        if not isinstance(class3_configs, list):
            class3_configs = [class3_configs]
        for cfg in class3_configs:
            # TODO: Run this thread for session_duration time
            t = threading.Thread(target=generate_class3_traffic, args=(cfg, verbose, ctx.obj.get('src_ip'),  stop_event, session_duration))
            threads.append(t)
            t.start()

    # stop the thread, send a stop event
    time.sleep(session_duration * 60)
    stop_event.set()

    try:
        # Wait for all threads to complete
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        click.echo("Generation stopped by user!")

# Define the CIPPacketGenerator class
class CIPPacketGenerator(click.Group):
    """
    A class for managing and grouping CIP packet generator commands in a Click command-line interface.

    This class extends `click.Group` and serves as a container for subcommands specific to the CIP packet generator domain. It allows the inclusion of multiple commands to provide functionality such as interactive and concurrent operations.

    Methods:
        __init__(*args, **kwargs):
            Initializes the CIPPacketGenerator group, adding predefined commands (`interactive` and `concurrent`) to the group.

    Attributes:
        Standard attributes inherited from `click.Group`.
    """
    def __init__(self, *args, **kwargs):
        super(CIPPacketGenerator, self).__init__(*args, **kwargs)
        self.add_command(interactive)
        self.add_command(concurrent)

# Main CLI group with verbose flag
@click.command(cls=CIPPacketGenerator)
@click.option('--verbose', is_flag=True, help='Print packet response on the CLI.')
@click.pass_context
def cli(ctx, verbose):
    """CLI tool to generate CIP traffic."""
    ctx.ensure_object(dict)
    ctx.obj['VERBOSE'] = verbose
    ctx.obj['src_ip'] = conf.route.route("0.0.0.0")[1]


if __name__ == '__main__':
    """
        Initialize the CLI object
    """
    cli()

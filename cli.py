import click
import threading
import json
from pydantic import ValidationError
from scapy_cip_enip.cip import CIP_Path
import time

from class3 import gen_class_3_cip_packet, randomize_service
from cli_types import Class0, Class1, Class3, MainModel
from utils import random_interval_between

"""
Add a verbose flag to print the packet response on the CLI itself.
TODO: Add verbose logging
"""

# Placeholder functions for generating traffic
def generate_class0_traffic(cfg, verbose, stop_event, session_duration):
    # Placeholder for generating class 0 traffic
    click.echo(f"Generating class 0 traffic from {cfg.src_ip} to {cfg.dst_ip}")
    start_time = time.time()
    session_duration_seconds = session_duration * 60
    while not stop_event.is_set() and (time.time() - start_time) < session_duration_seconds:
        print(".", end="", flush=True)
        time.sleep(cfg.rpi / 1000.0)

    if verbose:
        pass

def generate_class1_traffic(cfg, verbose, stop_event, session_duration):
    # Placeholder for generating class 1 traffic
    click.echo(f"Generating class 1 traffic from {cfg.src_ip} to {cfg.dst_ip} with rpi {cfg.rpi}")
    start_time = time.time()
    session_duration_seconds = session_duration * 60
    while not stop_event.is_set() and (time.time() - start_time) < session_duration_seconds:
        print(".", end="", flush=True)
        time.sleep(cfg.rpi / 1000.0)

    if verbose:
        pass

def generate_class3_traffic(cfg, verbose, stop_event, session_duration):
    # Placeholder for generating class 3 traffic
    click.echo(f"Generating class 3 traffic from {cfg.src_ip}:{cfg.sport} to {cfg.dst_ip}:{cfg.dport} with rpi none")
    kwargs = {
        "src_ip" : str(cfg.src_ip),
        "dst_ip" : str(cfg.dst_ip),
        "sport" : int(cfg.sport),
        "dport" : int(cfg.dport),
        "service" : randomize_service()
    }
    start_time = time.time()
    session_duration_seconds = session_duration * 60
    while not stop_event.is_set() and (time.time() - start_time) < session_duration_seconds:
        print(".", end="", flush=True)
        time.sleep(random_interval_between(cfg.min_random, cfg.max_random))

    if verbose:
        pass

    if verbose:
        click.echo("Packet response: ...")

# Interactive mode command
@click.command()
@click.pass_context
def interactive(ctx):
    """Interactive mode to generate a single type of CIP traffic."""
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
        src_ip = click.prompt('Enter src_ip', type=str)
        dst_ip = click.prompt('Enter dst_ip', type=str)
        rpi = click.prompt('Enter rpi', type=int)

        # Validate IP addresses
        try:
            data = {'src_ip': src_ip, 'dst_ip': dst_ip, 'rpi': rpi}
            class0_obj = Class0(**data)
        except ValidationError as e:
            click.echo(f"Invalid input:\n{e}")
            return
        # Generate traffic
        t = threading.Thread(target=generate_class0_traffic, args=(class0_obj, verbose, stop_event, session_duration))
        t.start()
        # stop the thread, send a stop event
        time.sleep(session_duration * 60)
        stop_event.set()


    elif class_choice == '1':
        # Prompt for src_ip, dst_ip, rpi
        src_ip = click.prompt('Enter src_ip', type=str)
        dst_ip = click.prompt('Enter dst_ip', type=str)
        rpi = click.prompt('Enter rpi', type=int)
        # Validate inputs
        try:
            data = {'src_ip': src_ip, 'dst_ip': dst_ip, 'rpi': rpi}
            class1_obj = Class1(**data)
        except ValidationError as e:
            click.echo(f"Invalid input:\n{e}")
            return
        # Generate traffic
        t = threading.Thread(target=generate_class0_traffic, args=(class1_obj, verbose, stop_event, session_duration))
        t.start()
        # stop the thread, send a stop event
        time.sleep(session_duration * 60)
        stop_event.set()


    elif class_choice == '3':
        # Prompt for src_ip, dst_ip, source_port, dest_port, rpi
        src_ip = click.prompt('Enter src_ip', type=str)
        dst_ip = click.prompt('Enter dst_ip', type=str)
        source_port = click.prompt('Enter source_port', type=int)
        dest_port = click.prompt('Enter dest_port', type=int)
        min_random = click.prompt('Enter min time (in seconds)', type=int)
        max_random = click.prompt('Enter max time  (in seconds)', type=int)
        # Validate inputs
        try:
            data = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'sport': source_port,
                'dport': dest_port,
                'min_random': min_random,
                'max_random': max_random,
            }
            class3_obj = Class3(**data)
        except ValidationError as e:
            click.echo(f"Invalid input:\n{e}")
            return
        # Generate traffic
        t = threading.Thread(target=generate_class3_traffic, args=(class3_obj, verbose, stop_event, session_duration))
        t.start()
        # stop the thread, send a stop event
        time.sleep(session_duration * 60)
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
def concurrent(ctx, config, session_duration):
    """Concurrent mode to generate multiple types of CIP traffic from a config file."""
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
            t = threading.Thread(target=generate_class0_traffic, args=(cfg, verbose, stop_event, session_duration))
            threads.append(t)
            t.start()

    # Process class1 configurations
    if validated_data.class1:
        class1_configs = validated_data.class1
        if not isinstance(class1_configs, list):
            class1_configs = [class1_configs]
        for cfg in class1_configs:
            # TODO: Run this thread for session_duration time
            t = threading.Thread(target=generate_class1_traffic, args=(cfg, verbose, stop_event, session_duration))
            threads.append(t)
            t.start()

    # Process class3 configurations
    if validated_data.class3:
        class3_configs = validated_data.class3
        if not isinstance(class3_configs, list):
            class3_configs = [class3_configs]
        for cfg in class3_configs:
            # TODO: Run this thread for session_duration time
            t = threading.Thread(target=generate_class3_traffic, args=(cfg, verbose, stop_event, session_duration))
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

if __name__ == '__main__':
    """
        Initialize the CLI object
    """
    cli()

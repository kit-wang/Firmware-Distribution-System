#!/usr/bin/env python
"""
Firmware Updater Tool

A frame consists of four sections:
1. Two bits for the mode (0 for setup, 1 for data transmission, 2 for authentication tag) of the data section
2. A six-it long section defining the size of data packet sent
3. A section of the encyrpted data, which includes the HMAC, firmware, and release message
4. One null byte at the conclusion of the data packet

Data Structure

[  0x02  ][     0x30     ][                variable                ][        0x20        ]
==========================================================================================
| version |     HMAC     |     Firmware      |   Release Message   |       auth tag
==========================================================================================

Frame Structure

[  2 bits  ][  6 bits  ][       62 bytes       ][   1 byte   ]
===============================================================
|   mode   |    size    |         data         |  null byte  |
===============================================================

In our case, the data is from one line of the Intel Hex formated .hex file

We write a frame to the bootloader, then wait for it to respond with an
OK message so we can write the next frame. The OK message in this case is
just a zero
"""

import argparse
import struct
import time

from serial import Serial

RESP_OK = b'\x00'
FRAME_SIZE = 62


# def send_setup(ser, setup_frame, debug=False):
#     ser.write(setup_frame)
    
#     # Send size and version to bootloader.
#     if debug:
#         print(setup_frame)

#     # Wait for an OK from the bootloader.
#     resp = ser.read()
#     time.sleep(0.1)
#     if resp != RESP_OK:
#         raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))


def send_frame(ser, frame, debug=False):
    ser.write(frame)  # Write the frame...

    if debug:
        print(frame)

    resp = ser.read()  # Wait for an OK from the bootloader
    time.sleep(0.1)
    # If the response is not OK, throw an error
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))


def main(ser, infile, debug):
    ser.write(b'U')  
    print('Waiting for bootloader to enter update mode...')
    if ser.read(1).decode() != 'U':
        return
    #print("sending data")
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, 'rb') as fp:
        firmware_blob = fp.read()
    data = firmware_blob[2:]
    
    # Send the version frame
    frame_meta = 3 << 6 #0b11000000
    #print(f"version frame meta: {frame_meta}")
    version = firmware_blob[0] | (firmware_blob[1] << 8)
    setup_frame = struct.pack('<BH60ss', frame_meta, version, bytes(60), bytes(1))
    send_frame(ser, setup_frame, debug=debug)
    
    # Send the setup frame
    frame_meta = 0b00000000
    # The one-byte long frame-based metadata is represented as a string, 
    # which the bootloader may read it and convert back to its bin ASCII representation
    
    firmware_no_tag = data[:-16]
    setup_frame = struct.pack('<sH60ss', chr(frame_meta).encode(), len(firmware_no_tag), bytes(60), bytes(1))
    send_frame(ser, setup_frame, debug=debug)
    
    for frame_start in range(0, len(firmware_no_tag), FRAME_SIZE):
        chunk = firmware_no_tag[frame_start: frame_start + FRAME_SIZE]
        
        length = len(chunk)
        frame_meta = 0b01000000 + length
        frame_fmt = '<B62ss'

        # Construct frame.
        frame = struct.pack(frame_fmt, frame_meta, chunk + bytes(62 - length), bytes(1))

        if debug:
            print("Writing frame {} ({} bytes)...".format(idx, len(frame)))

        send_frame(ser, frame, debug=debug)
    """
    
    for idx, frame_start in enumerate(range(0, len(data), FRAME_SIZE)):
        chunk = data[frame_start: frame_start + FRAME_SIZE]
        
        if len(data) - (1 + frame_start + 16) < 62:
            chunk = data[frame_start: -16]

        # Get frame logistics.
        length = len(chunk)
        frame_meta = 0b01000000 + length
        frame_fmt = '<B62ss'

        # Construct frame.
        frame = struct.pack(frame_fmt, frame_meta, chunk + bytes(62 - length), bytes(1))

        if debug:
            print("Writing frame {} ({} bytes)...".format(idx, len(frame)))

        send_frame(ser, frame, debug=debug)
    """
    # Send authentication tag frame.
    frame_meta = 0b10010000 
    auth_frame = struct.pack('<B62ss', frame_meta, data[-16:] + bytes(46), bytes(1))
    send_frame(ser, auth_frame, debug=debug)
    
    print("Done writing firmware.")
    

    # Send a zero length payload to tell the bootlader to finish writing its page.
    ser.write(struct.pack('>H', 0x0000))

    return ser


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')

    parser.add_argument("--port", help="Serial port to send update over.",
                        required=True)
    parser.add_argument("--firmware", help="Path to firmware image to load.",
                        required=True)
    parser.add_argument("--debug", help="Enable debugging messages.",
                        action='store_true')
    args = parser.parse_args()

    print('Opening serial port...')
    ser = Serial(args.port, baudrate=115200, timeout=2)
    # add auth tag 
    main(ser=ser, infile=args.firmware, debug=args.debug)



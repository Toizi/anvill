#!/usr/bin/env python3

# Copyright (c) 2020 Trail of Bits, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import unittest
import subprocess
import argparse
import tempfile
import os
import platform
import sys
import shutil
import pathlib
import time

from queue import Queue, Empty
from threading import Thread

class RunError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return str(self.msg)


def write_command_log(cmd_description, cmd_exec, ws):
    with open(os.path.join(ws, "commands.log"), "a") as cmdlog:
        if cmd_description:
            cmdlog.write(f"# {cmd_description}\n")
        cmdlog.write(f"{cmd_exec}\n")

def run_cmd(cmd, timeout, description, ws):
    try:
        exec_cmd = f"{' '.join(cmd)}"
        sys.stdout.write(f"Running: {exec_cmd}\n")
        write_command_log(description, exec_cmd, ws)
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            universal_newlines=True,
        )
    except FileNotFoundError as e:
        raise RunError('Error: No such file or directory: "' + e.filename + '"')
    except PermissionError as e:
        raise RunError('Error: File "' + e.filename + '" is not an executable.')

    return p

def run_async(cmd, description, ws, log_name=None):
    try:
        exec_cmd = f"{' '.join(cmd)}"
        sys.stdout.write(f"Running: {exec_cmd}\n")
        write_command_log(description, exec_cmd, ws)
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1, # line-buffered
        )
    except FileNotFoundError as e:
        raise RunError('Error: No such file or directory: "' + e.filename + '"')
    except PermissionError as e:
        raise RunError('Error: File "' + e.filename + '" is not an executable.')

    # we can't use communicate to get the output since the process will need to
    # continue running and communicate blocks until the process exits.
    # reading the output in a separate thread allows us to read the output
    # without blocking on the read and terminate the process after timeout
    # taken from https://stackoverflow.com/a/4896288
    q = Queue()
    def enqueue_output():
        f = None
        try:
            if log_name:
                f = open(os.path.join(ws, log_name), 'w')

            for line in iter(p.stdout.readline, b''):
                if f: f.write(line)
                q.put(line)
        except ValueError:
            pass
        finally:
            if f:
                f.close()

    t = Thread(target=enqueue_output)
    t.daemon = True
    t.start()

    return p, q


def compile(self, clang, input, output, timeout, ws, options=None):
    cmd = []
    cmd.append(clang)
    if options is not None:
        cmd.extend(options)
    cmd.extend([input, "-o", output])
    p = run_cmd(cmd, timeout, description="Original source Clang compile command", ws=ws)

    self.assertEqual(p.returncode, 0, "clang failure")
    self.assertEqual(
        len(p.stderr), 0, "errors or warnings during compilation: %s" % p.stderr
    )

    return p


def specify(self, specifier, input, output, timeout, ws):
    cmd = list(specifier) if isinstance(specifier, list) else [specifier]
    cmd.extend(["--bin_in", input])
    cmd.extend(["--spec_out", output])
    cmd.extend(["--entry_point", "main"])
    cmd.extend(["--refs_as_defs"])
    p = run_cmd(cmd, timeout, description="Spec generation command", ws=ws)

    self.assertEqual(p.returncode, 0, "specifier failure: %s" % p.stderr)
    self.assertEqual(
        len(p.stderr), 0, "errors or warnings during specification: %s" % p.stderr
    )

    return p

def spawn_ghidra_headless(self, input, timeout, ws):
    analyzer_path = pathlib.Path(os.environ.get('GHIDRA_PATH')) / 'support/analyzeHeadless'
    if not analyzer_path.exists():
        raise RunError('path to headless analyzer does not exist. Is GHIDRA_PATH set correctly?')
    bridge_path = pathlib.Path('~/ghidra_scripts/ghidra_bridge_server.py').expanduser()
    if not bridge_path.exists():
        raise RunError('path to ghidra bridge server does not exist. '\
            'Needs to be installed at $HOME/ghidra_scripts/ghidra_bridge_server.py')

    enable_decomp_id_path = pathlib.Path(ws) / 'enable_decompiler_id.py'
    with open(enable_decomp_id_path, 'w') as f:
        f.write('setAnalysisOption(currentProgram, "Decompiler Parameter ID", "true")\n')

    cmd = [
        str(analyzer_path),
        ws, # directory of the ghidra project files
        'roundtrip', # name of the project
        '-preScript', str(enable_decomp_id_path),
        '-postScript', str(bridge_path),
        '-import', input
    ]
    p, q = run_async(cmd, description="Ghidra analysis in background", ws=ws,
                    log_name='ghidra_headless.log')
    return p, q


def specify_ghidra(self, specifier, input, output, timeout, ws):

    # spawn ghidra in the background with ghidra_bridge running so our client
    # can use this instance
    proc, stdout_queue = spawn_ghidra_headless(self, input, timeout, ws)
    with proc as bg_proc:

        polling_interval = 1
        success = False
        for _ in range(timeout or 30//polling_interval):
            time.sleep(polling_interval)
            while True:
                try:
                    line = stdout_queue.get_nowait()
                except Empty:
                    break
                if 'ghidra_bridge_server.py (HeadlessAnalyzer)' in line:
                    success = True
                    break
            if success:
                break
        if success:
            # sleep a bit to give it time to properly connect since the string
            # we are looking for just signals that it is ready to receive a
            # connection
            time.sleep(3)
        else:
            raise RunError('Killed ghidra since we never received the ghidra_bridge_server output.'\
                        'Something must have gone wrong')



        cmd = list(specifier) if isinstance(specifier, list) else [specifier]
        cmd.extend(["--bin_in", input])
        cmd.extend(["--spec_out", output])
        cmd.extend(["--entry_point", "main"])
        cmd.extend(["--analyzer", "ghidra"])
        cmd.extend(["--refs_as_defs"])
        cmd.extend(["--shutdown-ghidra-bridge"])
        p = run_cmd(cmd, timeout, description="Spec generation command", ws=ws)

        # our spec generation should shut down the bridge, leading to a process exit
        err = False
        try:
            print('waiting for process to exit')
            ghidra_p = bg_proc.wait(timeout=5)
            self.assertEqual(ghidra_p, 0, 'Ghidra failure: %s' % p.stderr)
        except subprocess.TimeoutExpired:
            # if it didn't exit, something must have gone wrong
            bg_proc.kill()
            print(p.stdout)
            err = True
        if err:
            raise RunError('Killed ghidra since it did not shut down after spec generation.'\
                        'Something must have gone wrong')

    self.assertEqual(p.returncode, 0, "specifier failure: %s" % p.stderr)
    self.assertEqual(
        len(p.stderr), 0, "errors or warnings during specification: %s" % p.stderr
    )

    return p


def decompile(self, decompiler, input, output, timeout, ws):
    cmd = [decompiler]
    cmd.extend(["--spec", input])
    cmd.extend(["--bc_out", output])
    p = run_cmd(cmd, timeout, description="Decompilation command", ws=ws)

    self.assertEqual(p.returncode, 0, "decompiler failure: %s" % p.stderr)
    self.assertEqual(
        len(p.stderr), 0, "errors or warnings during decompilation: %s" % p.stderr
    )

    return p


def roundtrip(self, specifier, decompiler, filename, testname, clang, timeout, workspace, analyzer):

    # Python refuses to add delete=False to the TemporaryDirectory constructor
    #with tempfile.TemporaryDirectory(prefix=f"{testname}_", dir=workspace) as tempdir:
    tempdir = tempfile.mkdtemp(prefix=f"{testname}_", dir=workspace)

    compiled = os.path.join(tempdir, f"{testname}_compiled")
    compile(self, clang, filename, compiled, timeout, tempdir)

    # capture binary run outputs
    compiled_output = run_cmd([compiled], timeout, description="capture compilation output", ws=tempdir)

    rt_json = os.path.join(tempdir, f"{testname}_rt.json")
    if analyzer == 'binja':
        specify(self, specifier, compiled, rt_json, timeout, tempdir)
    elif analyzer == 'ghidra':
        specify_ghidra(self, specifier, compiled, rt_json, timeout, tempdir)

    rt_bc = os.path.join(tempdir, f"{testname}_rt.bc")
    decompile(self, decompiler, rt_json, rt_bc, timeout, tempdir)

    rebuilt = os.path.join(tempdir, f"{testname}_rebuilt")
    compile(self, clang, rt_bc, rebuilt, timeout, tempdir, ["-Wno-everything"]) 
    # capture outputs of binary after roundtrip
    rebuilt_output = run_cmd([rebuilt], timeout, description="Capture binary output after roundtrip", ws=tempdir)

    # Clean up tempdir if no workspace specified
    # otherwise keep it for debugging purposes
    if not workspace:
        shutil.rmtree(tempdir)

    self.assertEqual(compiled_output.stderr, rebuilt_output.stderr, "Different stderr")
    self.assertEqual(compiled_output.stdout, rebuilt_output.stdout, "Different stdout")
    self.assertEqual(compiled_output.returncode, rebuilt_output.returncode, "Different return code")


class TestRoundtrip(unittest.TestCase):
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("anvill", help="path to anvill-decompile-json")
    parser.add_argument("tests", help="path to test directory")
    parser.add_argument("clang", help="path to clang")
    parser.add_argument("workspace", nargs="?", default=None, help="Where to save temporary unit test outputs")
    parser.add_argument("-t", "--timeout", help="set timeout in seconds", type=int)
    parser.add_argument("--analyzer", help="analyzer to use",
        choices=['binja', 'ghidra'], default='binja')

    args = parser.parse_args()

    if args.workspace:
        os.makedirs(args.workspace)

    def test_generator(path, test_name):
        def test(self):
            specifier = ["python3", "-m", "anvill"]
            roundtrip(self, specifier, args.anvill, path, test_name, args.clang, args.timeout, args.workspace, args.analyzer)

        return test

    for item in os.scandir(args.tests):
        test_name = "test_%s" % os.path.splitext(item.name)[0]
        test = test_generator(item.path, test_name)
        setattr(TestRoundtrip, test_name, test)

    unittest.main(argv=[sys.argv[0], "-v"])

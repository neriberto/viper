# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

import base64
import json
import os
import r2pipe

from viper.common.abstracts import Module
from viper.core.session import __sessions__


class Radare(Module):
    cmd = 'r2'
    description = 'Start Radare2'
    authors = ['dukebarman', 'Raphaël Vinot']

    def __init__(self):
        super(Radare, self).__init__()
        self.parser.add_argument('command', nargs='*', help='Run a radare2 command on the current file')
        self.parser.add_argument('-b', '--binary', action='store_true', help='Binary info')
        self.parser.add_argument('-i', '--imports', action='store_true', help='Imports')
        self.parser.add_argument('-e', '--exports', action='store_true', help='Exports')
        self.parser.add_argument('-f', '--functions', action='store_true', help='Show all functions')
        self.parser.add_argument('-H', '--headers', action='store_true', help='Show headers')
        self.parser.add_argument('-r', '--relocs', action='store_true', help='Show relocs')
        self.parser.add_argument('-R', '--resources', action='store_true', help='Show resources')
        self.parser.add_argument('-s', '--sections', action='store_true', help='Show sections')
        self.parser.add_argument('-S', '--segments', action='store_true', help='Show segments')
        self.parser.add_argument('-y', '--symbols', action='store_true', help='Show symbols')
        self.parser.add_argument('-w', '--strings', action='store_true', help='Show all strings')

    def open_radare(self):
        command_line = 'r2 {}'.format(__sessions__.current.file.path)
        try:
            os.system(command_line)
        except Exception:
            self.log('error', "Unable to start Radare2")

    def get_command(self, command):
        r = r2pipe.open(__sessions__.current.file.path)
        return r.cmd(command)

    def command(self, command):
        r = r2pipe.open(__sessions__.current.file.path)
        self.log('info', r.cmd(command))

    def run(self):
        super(Radare, self).run()
        if self.args is None:
            return

        if self.args.binary: self.log('info', self.get_command('i'))
        if self.args.imports: self.log('info', self.get_command('ii'))
        if self.args.exports: self.log('info', self.get_command('iE'))
        if self.args.headers: self.log('info', self.get_command('ih'))
        if self.args.relocs: self.log('info', self.get_command('ir'))
        if self.args.resources: self.log('info', self.get_command('iR'))
        if self.args.sections: self.log('info', self.get_command('iS entropy, md5'))
        if self.args.segments: self.log('info', self.get_command('iSS entropy, md5'))
        if self.args.symbols: self.log('info', self.get_command('is'))

        if self.args.functions:
            r = r2pipe.open(__sessions__.current.file.path)
            out = json.loads(r.cmd('aaa;aflj'))
            header = ['offset', 'name', 'size', 'type']
            rows = []
            for o in out:
                rows.append(list([o[h] for h in header]))

            self.log('table', dict(header=header, rows=rows))

            return

        if self.args.strings:
            r = r2pipe.open(__sessions__.current.file.path)
            out = json.loads(r.cmd('izzj'))['strings']
            header = out[0].keys()
            rows = []
            for o in out:
                """
                if o['type'] == 'ascii':
                    o['string'] = base64.b64decode(o['string'])
                """
                rows.append(list([o[h] for h in header]))

            self.log('table', dict(header=header, rows=rows))

            return

        if self.args.command:
            r2command = ' '.join(self.args.command)
            if not __sessions__.is_set():
                if os.path.isfile(r2command):
                    __sessions__.new(r2command)
                    self.open_radare()
                    return
                else:
                    self.log('error', "No open session")
                    return

            if not r2command:
                self.open_radare()
            else:
                self.command(r2command)

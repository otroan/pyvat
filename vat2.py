#!/usr/bin/env python3

import cmd
from socket import inet_pton, inet_ntop, AF_INET6, AF_INET
import json
import argparse
import ipaddress
import shlex
from io import StringIO
import pprint
import sys
import os
import struct
import logging
import collections
import traceback
import warnings

try:
    import vpp_papi
except ImportError:
    # Perhaps we are in the source directory
    sys.path.append('src/vpp-api/python')
    import vpp_papi

OBJ_OPEN = '{'
OBJ_CLOSE = '}'

# generated with awk -F '[(,)]' 'BEGIN{print "VPP_API_ERRNO = {"}/^_/{printf "    %i: %s,\n", $3, $4}END{print "}"}' src/vnet/api_errno.h
VPP_API_ERRNO = {
    -1:  "Unspecified Error",
    -2:  "Invalid sw_if_index",
    -3:  "No such FIB / VRF",
    -4:  "No such inner FIB / VRF",
    -5:  "No such label",
    -6:  "No such entry",
    -7:  "Invalid value",
    -8:  "Invalid value #2",
    -9:  "Unimplemented",
    -10:  "Invalid sw_if_index #2",
    -11:  "System call error #1",
    -12:  "System call error #2",
    -13:  "System call error #3",
    -14:  "System call error #4",
    -15:  "System call error #5",
    -16:  "System call error #6",
    -17:  "System call error #7",
    -18:  "System call error #8",
    -19:  "System call error #9",
    -20:  "System call error #10",
    -30:  "Feature disabled by configuration",
    -31:  "Invalid registration",
    -50:  "Next hop not in FIB",
    -51:  "Unknown destination",
    -52:  "No paths specified in route",
    -53:  "Next hop not found",
    -54:  "No matching interface for probe",
    -55:  "Invalid VLAN",
    -56:  "VLAN subif already exists",
    -57:  "Invalid src address",
    -58:  "Invalid dst address",
    -59:  "Address length mismatch",
    -60:  "Address not found for interface",
    -61:  "Address not deletable",
    -62:  "ip6 not enabled",
    -63:  "No such graph node",
    -64:  "No such graph node #2",
    -65:  "No such table",
    -66:  "No such table #2",
    -67:  "No such table #3",
    -68:  "Subinterface already exists",
    -69:  "Subinterface creation failed",
    -70:  "Invalid memory size requested",
    -71:  "Invalid interface",
    -72:  "Invalid number of tags for requested operation",
    -73:  "Invalid argument",
    -74:  "Unexpected interface state",
    -75:  "Tunnel already exists",
    -76:  "Invalid decap-next",
    -77:  "Response not ready",
    -78:  "Not connected to the data plane",
    -79:  "Interface already exists",
    -80:  "Operation not allowed on slave of BondEthernet",
    -81:  "Value already exists",
    -82:  "Source and destination are the same",
    -83:  "IP6 multicast address required",
    -84:  "Segment routing policy name required",
    -85:  "Not running as root",
    -86:  "Connection to the data plane already exists",
    -87:  "Unsupported JNI version",
    -88:  "IP prefix invalid",
    -89:  "Invalid worker thread",
    -90:  "LISP is disabled",
    -91:  "Classify table not found",
    -92:  "Unsupported LISP EID type",
    -93:  "Cannot create pcap file",
    -94:  "Invalid adjacency type for this operation",
    -95:  "Operation would exceed configured capacity of ranges",
    -96:  "Operation would exceed capacity of number of ports",
    -97:  "Invalid address family",
    -98:  "Invalid sub-interface sw_if_index",
    -99:  "Table too big",
    -100:  "Cannot enable/disable feature",
    -101:  "Duplicate BFD object",
    -102:  "No such BFD object",
    -103:  "BFD object in use",
    -104:  "BFD feature not supported",
    -105:  "Address in use",
    -106:  "Address not in use",
    -107:  "Queue full",
    -108:  "Unsupported application config",
    -109:  "URI FIFO segment create failed",
    -110:  "RLOC address is local",
    -111:  "BFD object cannot be manipulated at this time",
    -112:  "Invalid GPE mode",
    -113:  "LISP GPE entries are present",
    -114:  "Address found for interface",
    -115:  "Session failed to connect",
    -116:  "Entry already exists",
    -117:  "Svm segment create fail",
    -118:  "Application not attached",
    -119:  "Bridge domain already exists",
    -120:  "Bridge domain has member interfaces",
    -121:  "Bridge domain 0 can't be deleted/modified",
    -122:  "Bridge domain ID exceeds 16M limit",
    -123:  "Subinterface doesn't exist",
    -124:  "Client already exist for L2 MACs events",
    -125:  "Invalid queue",
    -126:  "Unsupported",
    -127:  "Address already present on another interface",
    -128:  "Invalid application namespace",
    -129:  "Wrong app namespace secret",
    -130:  "Connect scope",
    -131:  "App already attached",
    -132:  "Redirect failed",
    -133:  "Illegal name",
    -134:  "No name servers configured",
    -135:  "Name server not found",
    -136:  "Name resolution not enabled",
    -137:  "Server format error",
    -138:  "No such name",
    -139:  "No addresses available",
    -140:  "Retry with new server",
    -141:  "Connect was filtered",
    -142:  "Inbound ACL in use",
    -143:  "Outbound ACL in use",
    -144:  "Initialization Failed",
    -145:  "Netlink error",
    -146:  "BIER bit-string-length unsupported",
    -147:  "Instance in use",
    -148:  "Session ID out of range",
    -149:  "ACL in use by a lookup context",
    -150:  "Invalid value #3",
    -151:  "Interface is not an Ethernet interface",
    -152:  "Bridge domain already has a BVI interface",
    -153:  "Invalid Protocol",
    -154:  "Invalid Algorithm",
    -155:  "Resource In Use",
    -156:  "invalid Key Length",
    -157:  "Unsupported FIB Path protocol",
    -159:  "Endian mismatch detected",
    -160:  "No change in table",
    -161:  "Missing certifcate or key",
    -162:  "limit exceeded",
    -163:  "port not managed by IKE",
    -164:  "UDP port already taken",
    -165:  "Retry stream call with cursor",
    -166:  "Invalid value #4",
}

interfaces = {}

def startup_init(vpp):
    # Create initial interface to ifindex mapping
    interfaces['default'] = 4294967295
    rv = vpp.api.sw_interface_dump()
    for i in rv:
        interfaces[i.interface_name] = i.sw_if_index

    # Register for changes
    rv = vpp.api.want_interface_events(enable_disable=1, pid=os.getpid())

def end(vpp):
    # Deregister for changes
    rv = vpp.api.want_interface_events(enable_disable=0, pid=os.getpid())
    print('RV', rv)

# From stackoverflow
class VATPrettyPrinter(pprint.PrettyPrinter):
    def format_namedtuple(self, object, stream, indent,
                          allowance, context, level):
        # Code almost equal to _format_dict, see pprint code
        write = stream.write
        write(object.__class__.__name__ + '(')
        object_dict = object._asdict()
        length = len(object_dict)
        if length:
            # We first try to print inline,
            # and if it is too large then we print it on multiple lines
            inline_stream = StringIO()
            self.format_namedtuple_items(object_dict.items(), inline_stream,
                                         indent, allowance + 1, context, level,
                                         inline=True)
            max_width = self._width - indent - allowance
            if len(inline_stream.getvalue()) > max_width:
                self.format_namedtuple_items(object_dict.items(), stream,
                                             indent, allowance + 1, context,
                                             level, inline=False)
            else:
                stream.write(inline_stream.getvalue())
        write(')')

    def format_namedtuple_items(self, items, stream, indent, allowance,
                                context, level, inline=False):
        # Code almost equal to _format_dict_items, see pprint code
        indent += self._indent_per_level
        write = stream.write
        last_index = len(items) - 1
        if inline:
            delimnl = ', '
        else:
            delimnl = ',\n' + ' ' * indent
            write('\n' + ' ' * indent)
        for i, (key, ent) in enumerate(items):
            if key == '_0' or key == 'context':
                continue
            last = i == last_index
            write(key + '=')
            self._format(ent, stream, indent + len(key) + 2,
                         allowance if last else 1,
                         context, level)
            if not last:
                write(delimnl)

    def _format(self, object, stream, indent, allowance, context, level):
        # We dynamically add the types of our namedtuple and namedtuple like
        # classes to the _dispatch object of pprint that maps classes to
        # formatting methods
        # We use a simple criteria (_asdict method) that allows us to use the
        # same formatting on other classes but a more precise one is possible
        if hasattr(object, '_asdict') and type(object).__repr__ not in self._dispatch:
            self._dispatch[type(object).__repr__] = VATPrettyPrinter.format_namedtuple
        super()._format(object, stream, indent, allowance, context, level)


pp = VATPrettyPrinter(indent=2)


def event_handler(message, event):
    pp.pprint(event)


class VATNoSuchInterfaceError(Exception):
    pass

class Format:
    def format_vl_api_address_t(args):
        return ipaddress.ip_address(args)

    def format_vl_api_ip6_address_t(args):
        return ipaddress.IPv6Address(args)

    def format_vl_api_ip4_address_t(args):
        return ipaddress.IPv4Address(args)

    def format_vl_api_ip6_prefix_t(args):
        return ipaddress.IPv6Network(args)

    def format_vl_api_ip4_prefix_t(args):
        return ipaddress.IPv4Network(args)

    def format_vl_api_interface_index_t(args):
        try:
            return int(args)
        except ValueError:
            try:
                return interfaces[args]
            except KeyError:
                raise VATNoSuchInterfaceError(args)

    def format_string(args):
        return args

    def format_u8(args):
        try:
            return int(args)
        except ValueError():
            return args.encode()

    def format_bool(args):
        return 1 if args else 0

    def format(typename, args):
        try:
            return getattr(Format, 'format_' + typename)(args)
        except AttributeError:
            return (int(args))


def mapargs(name, args):
    msg = vpp.messages[name]
    fields = msg.fields
    fields_by_name = msg.field_by_name
    i = 0
    a = {}
    while i < len(args):
        if args[i] in fields_by_name:
            # Convert args[i+1] to correct type
            index = fields.index(args[i])
            t = msg.fieldtypes[index]
            a[args[i]] = Format.format(t, args[i+1])
            i += 2
    return a


class VATShell(cmd.Cmd):
    intro = 'Welcome to the VAT shell.   Type help or ? to list commands.\n'
    prompt = 'vat# '
    file = None

    def __init__(self):
        cmd.Cmd.__init__(self)
        self.commands = sorted(vpp.services.keys())
        self.pp = VATPrettyPrinter(indent=2)
        self.commands = collections.OrderedDict()
        adds = frozenset(('add', 'is_add',
                          # bier
                          'bde_is_add', 'br_is_add', 'bdt_is_add', 'bt_is_add',
                          # mpls
                          'mt_is_add', 'mr_is_add'))
        dels = frozenset(('is_del',
                          # ioam
                          'dis'))
        empty = dict()
        for svc in sorted(vpp.services.keys()):
            cli = svc.replace('_', ' ')
            # remove the 'sw' prefix from sw_interface* APIs
            cli = cli.replace('sw ', '')
            cli = cli.replace('af packet ', 'afpacket ')
            cli = cli.replace('af xdp ', 'afxdp ')
            # FIXME: we might need the same for 'set' APIs?
            # add/del commands for add_del APIs
            if ' add del' in cli:
                cli_ = cli.replace(' add del', '')
                fields = frozenset(vpp.messages[svc].fields)
                add_ = adds & fields
                del_ = dels & fields
                assert(not (add_ and del_))
                if add_:
                    add_, = add_
                    self.commands[cli_ + ' add'] = (svc, {add_: 1})
                    self.commands[cli_ + ' del'] = (svc, {add_: 0})
                    continue
                elif del_:
                    del_, = del_
                    self.commands[cli_ + ' add'] = (svc, {del_: 0})
                    self.commands[cli_ + ' del'] = (svc, {del_: 1})
                    continue
                else:
                    print("Can't find is_add/is_del parameter for %s" % svc)
            self.commands[cli] = (svc, empty)

    def do_exit(self, s):
        'Exit the VAT shell'
        print()
        return True

    def do_exec(self, s):
        'Run a VPP debug cli command'
        rv = vpp.api.cli_inband(cmd=s)
        if rv.retval == 0:
            print(rv.reply)
        else:
            print('Command {} failed with {}'.format(s, rv.retval))

    def help_exit(self):
        print("Exit the interpreter.")
        print("You can also use the Ctrl-D shortcut.")

    do_EOF = do_exit
    help_EOF = help_exit

    def emptyline(self):
        pass

    def __parse_args(self, words):
        # build the arguments map and active path
        args = cur = collections.OrderedDict()
        tree = list()
        queue = list()
        for i in range(0, len(words), 2):
            k, v = words[i], words[i+1] if i+1 < len(words) else None
            if OBJ_OPEN == v:
                new = collections.OrderedDict()
                cur[k] = new
                queue.append(cur)
                cur = new
                tree.append(k)
            elif OBJ_CLOSE == k:
                tree.pop()
                cur = queue.pop()
                # in case we have }}
                if OBJ_CLOSE == v:
                    tree.pop()
                    cur = queue.pop()
            else:
                cur[k] = v
        return args, tree

    def __parse_line(self, line):
        # parse a line to retrieve service, arguments map and current active path
        # service is the API (with _ replaced by space)
        # arguments map is a tree of dict with each arg mapped to its value (including defaults)
        # active path is the current arg tree for autocomplete
        words = shlex.split(line)
        none = (None, None)
        for i in range(len(words), 0, -1):
            svc, defaults = self.commands.get(' '.join(words[:i]), none)
            if svc: break
        args, tree = self.__parse_args(words[i:])
        args.update(defaults)
        return (svc, args, tree)

    def default(self, line):
        svc, args, tree = self.__parse_line(line)

        try:
            f = getattr(vpp.api, svc)
        except AttributeError:
            print('command not found {}'.format(line))
            return

        try:
            a = mapargs(svc, args)
        except struct.error as err:
            print('invalid arguments {} {}'.format(line, err))
            return
        except VATNoSuchInterfaceError as err:
            print('No such interface {}'.format(err))
            return

        a.update(defaults)
        rv = f(**a)
        # streaming response is a list
        if not isinstance(rv, list):
            if rv.retval == 0:
                print('Success')
            else:
                print('Failure: ' + VPP_API_ERRNO.get(rv.retval, "unknown error") + " (error code %i)" % rv.retval)
        else:
            self.pp.pprint(rv)


    def __completedefault(self, text, line, begidx, endidx):
        # if the line matches commands, let's use that
        commands = self.completenames(line[:endidx], line, 0, endidx)
        if commands:
            return [c[begidx:] + " " for c in commands]

        # otherwise it should match a single command
        svc, args, tree = self.__parse_line(line)
        if not svc:
            return

        # creating a dict mapping fields names with fields type
        # we are skipping the 3 header fields
        fields = collections.OrderedDict(zip(vpp.messages[svc].fields[3:], vpp.messages[svc].fieldtypes[3:]))
        lastarg = None
        if lastarg in fields:
            i = fields.index(lastarg)
            t = fieldtypes[i]
            if t == 'u32':
                return ['0', '4294967296']
            if t == 'u8':
                return ['0', '255']
            if t == 'u16':
                return ['0', '65535']
            if t == 'vl_api_interface_index_t':
                if text:
                    return [intf for intf in list(interfaces)
                            if intf.startswith(text)]
                return list(interfaces)
        else:
            if tree:
                # we are in a complex subtype, autocomplete its fields
                for f in tree:
                    # go down the types tree...
                    t = vpp.get_type(fields[f])
                    fields = collections.OrderedDict(zip(t.fields, t.fieldtypes))
                params = [f for f in t.fields if f.startswith(text)]
            else:
                # otherwise autocomplete on top level fields
                params = [f for f in fields if f.startswith(text) and f not in args]
            if len(params) == 1:
                # if a single parameter matches and it is not a basic type, add object open to it
                t = vpp.get_type(fields[params[0]])
                if isinstance(t, vpp_papi.vpp_serializer.VPPType):
                    params = [params[0] + " " + OBJ_OPEN + " "]
            elif tree and not text:
                # we are in a complex subtype without any additional input, propose object close too
                params.append(OBJ_CLOSE)

        return params

    def completedefault(self, *args, **kwargs):
        try:
            return self.__completedefault(*args, **kwargs)
        except:
            print()
            traceback.print_exc()
            raise

    def completenames(self, text, line, begidx, endidx):
        return [c for c in self.commands if c.startswith(text)]

    def do_help(self, arg):
        if not arg:
            for k in self.commands:
                print(k)
        else:
            if arg in vpp.messages:
                print(vpp.messages[arg].msgdef)
                print(str(vpp.messages[arg]))
                print(repr(vpp.messages[arg]))
        super(VATShell, self).do_help(arg)


def socket_connect(socket_name, apidir):
    vpp_papi.VPPApiClient.apidir = apidir
    vpp = vpp_papi.VPPApiClient(server_address=socket_name)
    try:
        vpp.connect(name='vat')
    except Exception:
        print(f'Connect failed: {socket_name}')
        sys.exit(-1)
    return vpp

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='VPP API Tester CLI.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--socket-name", help="API socket name")
    parser.add_argument("--find-library", "-f", action='store_true',
                        help="Look hard for the vppapiclient library")
    parser.add_argument("--apidir", help="Directory for API files")
    parser.add_argument("--debug", "-d", help="Enable debugging", action="store_true")
    parser.add_argument("commands", nargs='*')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    vpp = socket_connect(args.socket_name, args.apidir)

    if args.commands:
        VATShell().onecmd(args.commands[0])
    else:
        vpp.register_event_callback(event_handler)
        startup_init(vpp)
        VATShell().cmdloop()
        end(vpp)

# Copyright (c) 2011 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""GDB support for Chrome types.

Add this to your gdb by amending your ~/.gdbinit as follows:
  python
  import sys
  sys.path.insert(0, "/path/to/tools/gdb/")
  import gdb_chrome
  end

Use
  (gdb) p /r any_variable
to print |any_variable| without using any printers.

To interactively type Python for development of the printers:
  (gdb) python foo = gdb.parse_and_eval('bar')
to put the C++ value 'bar' in the current scope into a Python variable 'foo'.
Then you can interact with that variable:
  (gdb) python print foo['impl_']
"""

import datetime
import gdb
import gdb.printing
import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..', '..', 'third_party', 'WebKit', 'Tools', 'gdb'))
try:
  import webkit
finally:
  sys.path.pop(0)

# When debugging this module, set the below variable to True, and then use
#   (gdb) python del sys.modules['gdb_chrome']
#   (gdb) python import gdb_chrome
# to reload.
_DEBUGGING = False


pp_set = gdb.printing.RegexpCollectionPrettyPrinter("chromium")


def typed_ptr(ptr):
    """Prints a pointer along with its exact type.

    By default, gdb would print just the address, which takes more
    steps to interpret.
    """
    # Returning this as a cast expression surrounded by parentheses
    # makes it easier to cut+paste inside of gdb.
    return '((%s)%s)' % (ptr.dynamic_type, ptr)


def yield_fields(val):
    """Use this in a printer's children() method to print an object's fields.

    e.g.
      def children():
        for result in yield_fields(self.val):
          yield result
    """
    try:
        fields = val.type.target().fields()
    except:
        fields = val.type.fields()
    for field in fields:
        if field.is_base_class:
            yield (field.name, val.cast(gdb.lookup_type(field.name)))
        else:
            yield (field.name, val[field.name])


class Printer(object):
    def __init__(self, val):
        self.val = val


class StringPrinter(Printer):
    def display_hint(self):
        return 'string'


class String16Printer(StringPrinter):
    def to_string(self):
        return webkit.ustring_to_string(self.val['_M_dataplus']['_M_p'])
pp_set.add_printer(
    'string16',
    '^string16|std::basic_string<(unsigned short|base::char16).*>$',
    String16Printer);


class GURLPrinter(StringPrinter):
    def to_string(self):
        return self.val['spec_']
pp_set.add_printer('GURL', '^GURL$', GURLPrinter)


class FilePathPrinter(StringPrinter):
    def to_string(self):
        return self.val['path_']['_M_dataplus']['_M_p']
pp_set.add_printer('FilePath', '^FilePath$', FilePathPrinter)


class SmartPtrPrinter(Printer):
    def to_string(self):
        return '%s%s' % (self.typename, typed_ptr(self.ptr()))


class ScopedPtrPrinter(SmartPtrPrinter):
    typename = 'scoped_ptr'
    def ptr(self):
        return self.val['impl_']['data_']['ptr']
pp_set.add_printer('scoped_ptr', '^scoped_ptr<.*>$', ScopedPtrPrinter)


class ScopedRefPtrPrinter(SmartPtrPrinter):
    typename = 'scoped_refptr'
    def ptr(self):
        return self.val['ptr_']
pp_set.add_printer('scoped_refptr', '^scoped_refptr<.*>$', ScopedRefPtrPrinter)


class LinkedPtrPrinter(SmartPtrPrinter):
    typename = 'linked_ptr'
    def ptr(self):
        return self.val['value_']
pp_set.add_printer('linked_ptr', '^linked_ptr<.*>$', LinkedPtrPrinter)


class WeakPtrPrinter(SmartPtrPrinter):
    typename = 'base::WeakPtr'
    def ptr(self):
        flag = ScopedRefPtrPrinter(self.val['ref_']['flag_']).ptr()
        if flag and flag['is_valid_']:
            return self.val['ptr_']
        return gdb.Value(0).cast(self.val['ptr_'].type)
pp_set.add_printer('base::WeakPtr', '^base::WeakPtr<.*>$', WeakPtrPrinter)


class CallbackPrinter(Printer):
    """Callbacks provide no usable information so reduce the space they take."""
    def to_string(self):
        return '...'
pp_set.add_printer('base::Callback', '^base::Callback<.*>$', CallbackPrinter)


class LocationPrinter(Printer):
    def to_string(self):
        return '%s()@%s:%s' % (self.val['function_name_'].string(),
                               self.val['file_name_'].string(),
                               self.val['line_number_'])
pp_set.add_printer('tracked_objects::Location', '^tracked_objects::Location$',
                   LocationPrinter)


class PendingTaskPrinter(Printer):
    def to_string(self):
        return 'From %s' % (self.val['posted_from'],)

    def children(self):
        for result in yield_fields(self.val):
            if result[0] not in ('task', 'posted_from'):
                yield result
pp_set.add_printer('base::PendingTask', '^base::PendingTask$',
                   PendingTaskPrinter)


class LockPrinter(Printer):
    def to_string(self):
        try:
            if self.val['owned_by_thread_']:
                return 'Locked by thread %s' % self.val['owning_thread_id_']
            else:
                return 'Unlocked'
        except gdb.error:
            return 'Unknown state'
pp_set.add_printer('base::Lock', '^base::Lock$', LockPrinter)


class TimeDeltaPrinter(object):
    def __init__(self, val):
        self._timedelta = datetime.timedelta(microseconds=int(val['delta_']))

    def timedelta(self):
        return self._timedelta

    def to_string(self):
        return str(self._timedelta)
pp_set.add_printer('base::TimeDelta', '^base::TimeDelta$', TimeDeltaPrinter)


class TimeTicksPrinter(TimeDeltaPrinter):
    def __init__(self, val):
        self._timedelta = datetime.timedelta(microseconds=int(val['us_']))
pp_set.add_printer('base::TimeTicks', '^base::TimeTicks$', TimeTicksPrinter)


class TimePrinter(object):
    def __init__(self, val):
        timet_offset = gdb.parse_and_eval(
            'base::Time::kTimeTToMicrosecondsOffset')
        self._datetime = (datetime.datetime.fromtimestamp(0) +
                          datetime.timedelta(microseconds=
                                             int(val['us_'] - timet_offset)))

    def datetime(self):
        return self._datetime

    def to_string(self):
        return str(self._datetime)
pp_set.add_printer('base::Time', '^base::Time$', TimePrinter)


class ManualConstructorPrinter(object):
    def __init__(self, val):
        self.val = val

    def to_string(self):
        return self.val['space_'].cast(self.val.type.template_argument(0))
pp_set.add_printer('base::ManualConstructor', '^base::ManualConstructor<.*>$', ManualConstructorPrinter)


class FlatTreePrinter(object):
    def __init__(self, val):
        self.val = val

    def to_string(self):
        # It would be nice to match the output of std::map which is a little
        # nicer than printing the vector of pairs. But iterating over it in
        # Python is much more complicated and this output is reasonable.
        # (Without this printer, a flat_map will output 7 lines of internal
        # template goop before the vector contents.)
        return 'base::flat_tree with ' + str(self.val['impl_']['body_'])
pp_set.add_printer('base::flat_map', '^base::flat_map<.*>$', FlatTreePrinter)
pp_set.add_printer('base::flat_set', '^base::flat_set<.*>$', FlatTreePrinter)
pp_set.add_printer('base::flat_tree', '^base::internal::flat_tree<.*>$',
                   FlatTreePrinter)


class ValuePrinter(object):
    def __init__(self, val):
        self.val = val

    def get_type(self):
        return self.val['type_']

    def to_string(self):
        typestr = str(self.get_type())
        # Trim prefix to just get the emum short name.
        typestr = typestr[typestr.rfind(':') + 1: ]

        if typestr == 'NONE':
            return 'base::Value of type NONE'
        if typestr == 'BOOLEAN':
            valuestr = self.val['bool_value_']
        if typestr == 'INTEGER':
            valuestr = self.val['int_value_']
        if typestr == 'DOUBLE':
            valuestr = self.val['double_value_']
        if typestr == 'STRING':
            valuestr = self.val['string_value_']
        if typestr == 'BINARY':
            valuestr = self.val['binary_value_']
        if typestr == 'DICTIONARY':
            valuestr = self.val['dict_']
        if typestr == 'LIST':
            valuestr = self.val['list_']

        return "base::Value of type %s = %s" % (typestr, str(valuestr))
pp_set.add_printer('base::Value', '^base::Value$', ValuePrinter)
pp_set.add_printer('base::ListValue', '^base::ListValue$', ValuePrinter)
pp_set.add_printer('base::DictionaryValue', '^base::DictionaryValue$',
                   ValuePrinter)


class IpcMessagePrinter(Printer):
    def header(self):
        return self.val['header_'].cast(
            gdb.lookup_type('IPC::Message::Header').pointer())

    def to_string(self):
        message_type = self.header()['type']
        return '%s of kind %s line %s' % (
            self.val.dynamic_type,
            (message_type >> 16).cast(gdb.lookup_type('IPCMessageStart')),
            message_type & 0xffff)

    def children(self):
        yield ('header_', self.header().dereference())
        yield ('capacity_after_header_', self.val['capacity_after_header_'])
        for field in self.val.type.fields():
            if field.is_base_class:
                continue
            yield (field.name, self.val[field.name])
pp_set.add_printer('IPC::Message', '^IPC::Message$', IpcMessagePrinter)


class NotificationRegistrarPrinter(Printer):
    def to_string(self):
        try:
            registrations = self.val['registered_']
            vector_finish = registrations['_M_impl']['_M_finish']
            vector_start = registrations['_M_impl']['_M_start']
            if vector_start == vector_finish:
                return 'Not watching notifications'
            if vector_start.dereference().type.sizeof == 0:
                # Incomplete type: b/8242773
                return 'Watching some notifications'
            return ('Watching %s notifications; '
                    'print %s->registered_ for details') % (
                        int(vector_finish - vector_start),
                        typed_ptr(self.val.address))
        except gdb.error:
            return 'NotificationRegistrar'
pp_set.add_printer('content::NotificationRegistrar',
                   '^content::NotificationRegistrar$',
                   NotificationRegistrarPrinter)


class SiteInstanceImplPrinter(object):
    def __init__(self, val):
        self.val = val.cast(val.dynamic_type)

    def to_string(self):
        return 'SiteInstanceImpl@%s for %s' % (
            self.val.address, self.val['site_'])

    def children(self):
        yield ('id_', self.val['id_'])
        yield ('has_site_', self.val['has_site_'])
        if self.val['browsing_instance_']['ptr_']:
            yield ('browsing_instance_', self.val['browsing_instance_']['ptr_'])
        if self.val['process_']:
            yield ('process_', typed_ptr(self.val['process_']))
pp_set.add_printer('content::SiteInstanceImpl', '^content::SiteInstanceImpl$',
                   SiteInstanceImplPrinter)


class RenderProcessHostImplPrinter(object):
    def __init__(self, val):
        self.val = val.cast(val.dynamic_type)

    def to_string(self):
        pid = ''
        try:
            child_process_launcher_ptr = (
                self.val['child_process_launcher_']['impl_']['data_']['ptr'])
            if child_process_launcher_ptr:
                context = (child_process_launcher_ptr['context_']['ptr_'])
                if context:
                    pid = ' PID %s' % str(context['process_']['process_'])
        except gdb.error:
            # The definition of the Context type may not be available.
            # b/8242773
            pass
        return 'RenderProcessHostImpl@%s%s' % (self.val.address, pid)

    def children(self):
        yield ('id_', self.val['id_'])
        yield ('listeners_',
               self.val['listeners_']['data_'])
        yield ('worker_ref_count_', self.val['worker_ref_count_'])
        yield ('fast_shutdown_started_', self.val['fast_shutdown_started_'])
        yield ('deleting_soon_', self.val['deleting_soon_'])
        yield ('pending_views_', self.val['pending_views_'])
        yield ('visible_widgets_', self.val['visible_widgets_'])
        yield ('backgrounded_', self.val['backgrounded_'])
        yield ('widget_helper_', self.val['widget_helper_'])
        yield ('is_initialized_', self.val['is_initialized_'])
        yield ('browser_context_', typed_ptr(self.val['browser_context_']))
        yield ('sudden_termination_allowed_',
               self.val['sudden_termination_allowed_'])
        yield ('ignore_input_events_', self.val['ignore_input_events_'])
        yield ('is_guest_', self.val['is_guest_'])
pp_set.add_printer('content::RenderProcessHostImpl',
                   '^content::RenderProcessHostImpl$',
                   RenderProcessHostImplPrinter)


gdb.printing.register_pretty_printer(gdb, pp_set, replace=_DEBUGGING)

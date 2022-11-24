# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     atobj
   Description :
   Author :       liaozhaoyan
   date：          2022/11/6
-------------------------------------------------
   Change Activity:
                   2022/11/6:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'


class CatObj(object):
    def __init__(self):
        self.atDict = {
            "DW_AT_producer": self._at_producer,
            "DW_AT_language": self._at_language,
            "DW_AT_name": self._at_name,
            "DW_AT_comp_dir": self._at_comp_dir,
            "DW_AT_low_pc": self._at_low_pc,
            "DW_AT_high_pc": self._at_high_pc,
            "DW_AT_stmt_list": self._at_stmt_list,
            "DW_AT_byte_size": self._at_byte_size,
            "DW_AT_encoding": self._at_encoding,
            "DW_AT_type": self._at_type,
            "DW_AT_sibling": self._at_sibling,
            "DW_AT_upper_bound": self._at_upper_bound,
            "DW_AT_decl_file": self._at_decl_file,
            "DW_AT_decl_line": self._at_decl_line,
            "DW_AT_decl_column": self._at_decl_column,
            "DW_AT_data_member_location": self._at_data_member_location,
            "DW_AT_bit_size": self._at_bit_size,
            "DW_AT_bit_offset": self._at_bit_offset,
            "DW_AT_const_value": self._at_const_value,
            "DW_AT_external": self._at_external,
            "DW_AT_prototyped": self._at_prototyped,
            "DW_AT_GNU_all_tail_call_sites": self._at_GNU_all_tail_call_sites,
            "DW_AT_location": self._at_location,
            "DW_AT_declaration": self._at_declaration,
            "DW_AT_frame_base": self._at_frame_base,
            "DW_AT_entry_pc": self._at_entry_pc,
            "DW_AT_call_file": self._at_call_file,
            "DW_AT_call_line": self._at_call_line,
            "DW_AT_call_column": self._at_call_column,
            "DW_AT_abstract_origin": self._at_abstract_origin,
            "DW_AT_ranges": self._at_ranges,
            "DW_AT_specification": self._at_specification,
            "DW_AT_GNU_all_call_sites": self._at_GNU_all_call_sites,
            "DW_AT_GNU_call_site_value": self._at_GNU_call_site_value,
            "DW_AT_GNU_tail_call": self._at_GNU_tail_call,
            "DW_AT_GNU_call_site_target": self._at_GNU_call_site_target,
            "DW_AT_inline": self._at_inline,
            "DW_AT_artificial": self._at_artificial,
            "DW_AT_linkage_name": self._at_linkage_name,
            "DW_AT_noreturn": self._at_noreturn,
            "DW_AT_alignment": self._at_alignment,
            "DW_AT_call_all_calls": self._at_call_all_calls,
            "DW_AT_GNU_locviews": self._at_GNU_locviews,
            "DW_AT_GNU_entry_view": self._at_GNU_entry_view,
            "DW_AT_call_return_pc": self._at_call_return_pc,
            "DW_AT_call_origin": self._at_call_origin,
            "DW_AT_call_value": self._at_call_value,
            "DW_AT_call_parameter": self._at_call_parameter,
            "DW_AT_count": self._at_count,
            "DW_AT_data_bit_offset": self._at_data_bit_offset,
            "DW_AT_call_all_tail_calls": self._at_call_all_tail_calls,
            "DW_AT_call_target": self._at_call_target,
            "DW_AT_GNU_vector": self._at_GNU_vector,
        }

    def _at_GNU_vector(self, values):
        return self._at_byte_size(values)

    def _at_call_target(self, values):
        return values

    def _at_call_all_tail_calls(self, values):
        return self._at_byte_size(values)

    def _at_data_bit_offset(self, values):
        return self._at_byte_size(values)

    def _at_count(self, values):
        return self._at_byte_size(values)

    def _at_call_parameter(self, values):
        return self._at_call_origin(values)

    def _at_call_value(self, values):
        return values

    def _at_call_origin(self, values):  # <0xda>
        return self._at_byte_size(values[1:-1])

    def _at_call_return_pc(self, values):  # addr
        return self._at_byte_size(values)

    def _at_GNU_entry_view(self, values):
        return self._at_byte_size(values)

    def _at_GNU_locviews(self, values):
        return self._at_byte_size(values)

    def _at_call_all_calls(self, values):
        return self._at_byte_size(values)

    def _at_alignment(self, values):
        return self._at_byte_size(values)

    def _at_noreturn(self, values):
        return self._at_byte_size(values)

    def _at_GNU_call_site_target(self, values):
        return values

    def _at_artificial(self, values):
        self._at_byte_size(values)

    def _at_linkage_name(self, values):
        try:
            self._at_producer(values)
        except ValueError:
            return values

    def _at_inline(self, values):
        return values

    def _at_GNU_tail_call(self, values):
        return values

    def _at_GNU_call_site_value(self, values):
        return values

    def _at_GNU_all_call_sites(self, values):
        return self._at_byte_size(values)

    def _at_specification(self, values):
        return self._at_type(values)

    def _at_ranges(self, values):
        return self._at_byte_size(values)

    def _at_abstract_origin(self, values):
        return self._at_type(values)

    def _at_call_column(self, values):
        return self._at_byte_size(values)

    def _at_call_line(self, values):
        return self._at_byte_size(values)

    def _at_call_file(self, values):
        return self._at_byte_size(values)

    def _at_entry_pc(self, values):
        return self._at_low_pc(values)

    def _at_producer(self, values):
        if "):" in values:
            _, value = values.split("):", 1)
            return value.strip()
        return values

    def _at_language(self, values):
        if values.startswith("("):
            _, value = values.rsplit("(", 1)
            return value[:-1]
        return values

    def _at_name(self, values):
        if len(values) and values[0] == '(':
            return self._at_producer(values)
        return values

    def _at_comp_dir(self, values):
        return self._at_producer(values)

    def _at_low_pc(self, values):
        return self._at_byte_size(values)

    def _at_high_pc(self, values):
        return int(values, 16)

    def _at_stmt_list(self, values):
        return self._at_high_pc(values)

    def _at_byte_size(self, values):
        try:
            if values.startswith("0x"):
                res = int(values, 16)
            else:
                res = int(values)
        except ValueError:
            res = values
        return res

    def _at_encoding(self, values):
        _, value = values.split("(", 1)
        return value[:-1]

    def _at_type(self, values):
        value = int(values[1:-1], 16)
        return value

    def _at_sibling(self, values):
        return self._at_type(values)

    def _at_upper_bound(self, values):
        return self._at_byte_size(values)

    def _at_decl_file(self, values):
        return self._at_byte_size(values)

    def _at_decl_line(self, values):
        return self._at_byte_size(values)

    def _at_decl_column(self, values):
        return self._at_byte_size(values)

    def _at_data_member_location(self, values):
        return self._at_byte_size(values)

    def _at_bit_size(self, values):
        return self._at_byte_size(values)

    def _at_bit_offset(self, values):
        return self._at_byte_size(values)

    def _at_const_value(self, values):
        try:
            return self._at_byte_size(values)
        except ValueError:
            return values

    def _at_external(self, values):
        return self._at_byte_size(values)

    def _at_prototyped(self, values):
        return self._at_byte_size(values)

    def _at_frame_base(self, values):
        return values

    def _at_GNU_all_tail_call_sites(self, values):
        return self._at_byte_size(values)

    def _at_location(self, values):
        return values

    def _at_declaration(self, values):
        return self._at_byte_size(values)

    def parse(self, tag, value):
        return self.atDict[tag](value)


if __name__ == "__main__":
    pass

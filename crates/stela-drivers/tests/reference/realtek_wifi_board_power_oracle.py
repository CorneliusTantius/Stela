#!/usr/bin/env python3
"""Unchanged pinned RTL8822C factory board power data oracle/exporter.
Usage: script reference-dir output-dir; no PHY, calibration or Linux ABI.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys
reference,out=map(pathlib.Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=True)
manifest=[]
def extract(file, name, kind=None):
    text = (reference / 'rtw88' / file).read_text()
    if kind:
        match = re.search(r'\b' + kind + r' ' + name + r'\s*\{', text)
        start, brace = match.start(), text.index('{', match.start())
    else:
        for match in re.finditer(r'\b' + name + r'\s*\(', text):
            end, depth = text.index('(', match.start()) + 1, 1
            while depth:
                depth += (text[end] == '(') - (text[end] == ')')
                end += 1
            while text[end].isspace():
                end += 1
            if text[end] != '{':
                continue
            start, brace = text.rfind('\n\n', 0, match.start()) + 2, end
            break
        else:
            raise ValueError(name)
    end, depth = brace + 1, 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    if kind:
        end = text.index(';', end) + 1
    body = text[start:end]
    manifest.append(dict(path='rtw88/' + file, symbol=name, sha256=hashlib.sha256(body.encode()).hexdigest()))
    return body



def span(file,start,end,symbol):
 text=(reference/'rtw88'/file).read_text();a=text.index(start);body=text[a:text.index(end,a)];manifest.append(dict(path='rtw88/'+file,symbol=symbol,sha256=hashlib.sha256(body.encode()).hexdigest()));return body

def array(file,name):
 text=(reference/'rtw88'/file).read_text();m=re.search(r'^static const [^;\n]+\b'+name+r'\s*\[.*?=\s*\{',text,re.M);assert m,name
 a=m.start();b=m.end();depth=1
 while depth:
  depth+=(text[b]=='{')-(text[b]=='}');b+=1
 b=text.index(';',b)+1;body=text[a:b];manifest.append(dict(path='rtw88/'+file,symbol=name,sha256=hashlib.sha256(body.encode()).hexdigest()));return body

def macro(file,name):
 line=re.search(r'^#define\s+'+name+r'\s+[^\n]+',(reference/'rtw88'/file).read_text(),re.M).group();manifest.append(dict(path='rtw88/'+file,symbol=name,sha256=hashlib.sha256(line.encode()).hexdigest()));return line

pg=array('rtw8822c_table.c','rtw8822c_bb_pg_type0');lmt0=array('rtw8822c_table.c','rtw8822c_txpwr_lmt_type0');lmt5=array('rtw8822c_table.c','rtw8822c_txpwr_lmt_type5')
# Exact numeric source rows, independent of native parsing/normalization.
rust='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Copyright(c) 2018-2019 Realtek Corporation\n// Factory power reference data from pinned rtw8822c_table.c; no OS authority.\n'
for body,name,ty in [(pg,'PG','u32'),(lmt0,'LIMIT0','i16'),(lmt5,'LIMIT5','i16')]:
 rows=[]
 for row in re.findall(r'\{([^{}]+)\}',body):
  values=[int(v.strip(),0)for v in row.split(',')if v.strip()];assert len(values)==6;rows.append(values)
 rust+='pub(super) const '+name+': &[[ '+ty+'; 6]] = &[\n'+''.join('    ['+', '.join(str(v)for v in row)+'],\n'for row in rows)+'];\n'
 manifest.append(dict(export=name,rows=len(rows)))
data=out/'data.rs';data.write_text(rust);subprocess.run(['rustfmt','--edition','2024',str(data)],check=True)
# The RTL8821C's PG and its one limit table, compared byte for byte with the
# committed module.
pg_8821c=array('rtw8821c_table.c','rtw8821c_bb_pg_type0');lmt_8821c=array('rtw8821c_table.c','rtw8821c_txpwr_lmt_type0')
rust_8821c='// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n// Copyright(c) 2018-2019 Realtek Corporation\n// Factory power reference data from pinned rtw8821c_table.c; no OS authority.\n//! RTL8821C factory power-reference tables from rtw8821c_table.c.\n'
for body,name,ty in [(pg_8821c,'PG','u32'),(lmt_8821c,'LIMIT0','i16')]:
 rows=[]
 for row in re.findall(r'\{([^{}]+)\}',body):
  values=[int(v.strip(),0)for v in row.split(',')if v.strip()];assert len(values)==6;rows.append(values)
 rust_8821c+='pub(super) const '+name+': &[[ '+ty+'; 6]] = &[\n'+''.join('    ['+', '.join(str(v)for v in row)+'],\n'for row in rows)+'];\n'
 manifest.append(dict(export='8821c '+name,rows=len(rows)))
data_8821c=out/'data_8821c.rs';data_8821c.write_text(rust_8821c);subprocess.run(['rustfmt','--edition','2024',str(data_8821c)],check=True)
native_8821c=pathlib.Path(__file__).resolve().parents[3]/'stela-driver-net/src/wifi/realtek/phy/board_power/data_8821c.rs'
assert data_8821c.read_bytes()==native_8821c.read_bytes(),'committed RTL8821C power tables differ from the pinned source export'
macros='\n'.join(macro('main.h',n)for n in ['RTW_RF_PATH_MAX','RTW_CHANNEL_WIDTH_MAX','RTW_MAX_CHANNEL_NUM_2G','RTW_MAX_CHANNEL_NUM_5G'])
declarations='\n'.join(extract(f,n,k)for f,n,k in [('main.h','rtw_rate_section','enum'),('main.h','rtw_bandwidth','enum'),('main.h','rtw_trx_desc_rate','enum'),('main.h','rtw_regulatory_domains','enum'),('phy.c','rtw_phy_band_type','enum'),('phy.h','rtw_phy_pg_cfg_pair','struct'),('phy.h','rtw_txpwr_lmt_cfg_pair','struct'),('regd.c','rtw_regd_alternative_t','struct')])
rates=span('phy.c','const u8 rtw_cck_rates[]','\nenum rtw_phy_band_type','all source rate/section/size arrays')
rates=re.sub(r'^EXPORT_SYMBOL\([^\n]+\);\n','',rates,flags=re.M)
channels=array('phy.c','rtw_channel_idx_5g')
alternate=span('regd.c','#define DECL_REGD_ALT','\nbool rtw_regd_has_alt','source alternative factory table mapping')
rfe=array('rtw8822c.c','rtw8822c_rfe_defs');mapping=re.findall(r'\[(\d+)\]\s*=\s*RTW_DEF_RFE\(8822c,\s*0,\s*(\d+),\s*0\)',rfe);assert mapping==[(str(i),'5'if i==5 else'0')for i in range(7)]
extract('main.c','rtw_chip_board_info_setup') # exact whole callsite context
chip=(reference/'rtw88/rtw8822c.c').read_text()
for key,value in [('max_power_index','0x7f'),('is_pwr_by_rate_dec','false'),('txgi_factor','2')]:
 line=re.search(r'^\s*\.'+key+r'\s*=\s*'+value+r',',chip,re.M).group();manifest.append(dict(path='rtw88/rtw8822c.c',symbol=key,sha256=hashlib.sha256(line.encode()).hexdigest()))
names=['tbl_to_dec_pwr_by_rate','rtw_phy_get_rate_values_of_txpwr_by_rate','rtw_phy_store_tx_power_by_rate','rtw_parse_tbl_bb_pg','rtw_channel_to_idx','rtw_phy_set_tx_power_limit','rtw_xref_5g_txpwr_lmt','rtw_xref_txpwr_lmt_by_rs','rtw_xref_5g_txpwr_lmt_by_ch','rtw_xref_txpwr_lmt_by_bw','rtw_xref_txpwr_lmt','__cfg_txpwr_lmt_by_alt','rtw_cfg_txpwr_lmt_by_alt','rtw_parse_tbl_txpwr_lmt','rtw_phy_tx_power_by_rate_config_by_path','rtw_phy_tx_power_by_rate_config','__rtw_phy_tx_power_limit_config','rtw_phy_tx_power_limit_config','rtw_phy_init_tx_power_limit','rtw_phy_init_tx_power']
functions=extract('regd.c','rtw_regd_has_alt')+'\n'+'\n'.join(extract('phy.c',n)for n in names)
preamble=r'''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef int8_t s8;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define WARN(x,...) do{if(x)abort();}while(0)
#define WARN_ON(x) ((x)?(abort(),1):0)
#define rtw_warn(...) ((void)0)
#define rtw_dbg(...) ((void)0)
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define clamp_t(t,v,a,b) ((t)(v)<(t)(a)?(t)(a):((t)(v)>(t)(b)?(t)(b):(t)(v)))
#define bcd2bin(v) (((u8)(v)&15)+((u8)(v)>>4)*10)
#define bcd_to_dec_pwr_by_rate(val,i) bcd2bin(val>>((i)*8))
/*DECLARATIONS*/
struct rtw_table {const void*data;u32 size;};
struct rtw_hal {
s8 tx_pwr_by_rate_offset_2g[4][DESC_RATE_MAX],tx_pwr_by_rate_offset_5g[4][DESC_RATE_MAX];
s8 tx_pwr_by_rate_base_2g[4][RTW_RATE_SECTION_NUM],tx_pwr_by_rate_base_5g[4][RTW_RATE_SECTION_NUM];
s8 tx_pwr_limit_2g[RTW_REGD_MAX][3][RTW_RATE_SECTION_NUM][14],tx_pwr_limit_5g[RTW_REGD_MAX][3][RTW_RATE_SECTION_NUM][49];u8 cch_by_bw[3];};
struct rtw_chip_info {u8 max_power_index;bool is_pwr_by_rate_dec;};
struct rtw_dev {struct rtw_chip_info*chip;struct rtw_hal hal;};
static u32 delays;static void msleep(u32 ms){delays+=ms;}
static void dump(FILE*f,struct rtw_hal*h){
#define OUT(member) if(fwrite(h->member,sizeof(h->member),1,f)!=1)abort()
OUT(tx_pwr_by_rate_offset_2g);OUT(tx_pwr_by_rate_offset_5g);OUT(tx_pwr_by_rate_base_2g);OUT(tx_pwr_by_rate_base_5g);OUT(tx_pwr_limit_2g);OUT(tx_pwr_limit_5g);OUT(cch_by_bw);
#undef OUT
}
'''
main=r'''int main(int argc,char**argv){if(argc!=2)return 2;FILE*f=fopen(argv[1],"wb");if(!f)abort();struct rtw_chip_info chip={127,false};struct rtw_dev d={.chip=&chip};
for(u32 rfe=0;rfe<7;rfe++){memset(&d.hal,0,sizeof(d.hal));struct rtw_table pg={rtw8822c_bb_pg_type0,ARRAY_SIZE(rtw8822c_bb_pg_type0)},lmt=rfe==5?(struct rtw_table){rtw8822c_txpwr_lmt_type5,ARRAY_SIZE(rtw8822c_txpwr_lmt_type5)}:(struct rtw_table){rtw8822c_txpwr_lmt_type0,ARRAY_SIZE(rtw8822c_txpwr_lmt_type0)};u32 header[4]={rfe,pg.size,lmt.size,0};delays=0;
rtw_phy_init_tx_power(&d);rtw_parse_tbl_bb_pg(&d,&pg);rtw_parse_tbl_txpwr_lmt(&d,&lmt);rtw_phy_tx_power_by_rate_config(&d.hal);rtw_phy_tx_power_limit_config(&d.hal);header[3]=delays;if(fwrite(header,sizeof(header),1,f)!=1)abort();dump(f,&d.hal);}
/* Sparse source sheets exercise alternative/WW defaults and repeated rows.
   These are data-oracle fixtures, never current jurisdiction authority. */
for(u32 c=0;c<64;c++){memset(&d.hal,0,sizeof(d.hal));struct rtw_phy_pg_cfg_pair pgrows[2]={{0,0,0,0xc20,0xffffffff,0x484c5054},{0,0,0,0xc24,0xffffffff,0x54585858}};struct rtw_txpwr_lmt_cfg_pair rows[3]={{0,0,0,0,1,(s8)(c-32)},{2,1,1,2,36,(s8)(64-c)},{0,0,0,0,1,(s8)(c-16)}};struct rtw_table pg={pgrows,2},lmt={rows,3};delays=0;rtw_phy_init_tx_power(&d);rtw_parse_tbl_bb_pg(&d,&pg);rtw_parse_tbl_txpwr_lmt(&d,&lmt);rtw_phy_tx_power_by_rate_config(&d.hal);rtw_phy_tx_power_limit_config(&d.hal);u32 header[4]={c,2,3,delays};if(fwrite(header,sizeof(header),1,f)!=1)abort();dump(f,&d.hal);}
if(fclose(f))abort();return 0;}
'''
source=out/'oracle.c';source.write_text(preamble.replace('/*DECLARATIONS*/',macros+'\n'+declarations)+'\n'+rates+'\n'+channels+'\n'+alternate+'\n'+pg+'\n'+lmt0+'\n'+lmt5+'\n'+functions+'\n'+main);exe=out/'oracle';subprocess.run(['clang','-std=gnu11','-O1','-g','-Wno-pointer-sign','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True);trace=out/'trace.bin';subprocess.run([str(exe),str(trace)],check=True)
manifest.append(dict(factory_cases=7,sparse_cases=64,trace_bytes=trace.stat().st_size,trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),data_bytes=data.stat().st_size,data_sha256=hashlib.sha256(data.read_bytes()).hexdigest(),scope='factory board PG/by-rate/base/all sheet limits only; no selected OS country/current channel or TX authority'))
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest[-1]))

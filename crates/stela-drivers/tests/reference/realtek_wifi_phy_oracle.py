#!/usr/bin/env python3
"""Pinned unchanged RTL8822C pre-TRX PHY table initialization oracle.
Usage: script reference-dir output-dir. Post-TRX/calibration functions are
explicitly inert after the recorded phase; no radio or Linux ABI proof.
"""
import hashlib,json,pathlib,re,subprocess,sys
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




def macro(file,name):
    text=(reference/'rtw88'/file).read_text()
    line=re.search(r'^#define\s+'+name+r'\s+[^\n]+',text,re.M).group()
    manifest.append(dict(path='rtw88/'+file,symbol=name,sha256=hashlib.sha256(line.encode()).hexdigest()))
    return line
macros='\n'.join(macro(file,name) for file,name in [('main.h','RFREG_MASK'),('main.h','INV_RF_DATA'),('reg.h','REG_SYS_FUNC_EN'),('reg.h','BIT_FEN_BB_GLB_RST'),('reg.h','BIT_FEN_BB_RSTB'),('reg.h','REG_RF_CTRL'),('reg.h','BIT_RF_EN'),('reg.h','BIT_RF_RSTB'),('reg.h','BIT_RF_SDM_RSTB'),('reg.h','REG_WLRF1'),('reg.h','BIT_WLRF1_BBRF_EN'),('reg.h','REG_DIS_DPD'),('reg.h','DIS_DPD_MASK'),('reg.h','DIS_DPD_RATEALL'),('reg.h','REG_ANAPAR_XTAL_0'),('rtw8822c.h','REG_3WIRE'),('rtw8822c.h','REG_3WIRE2'),('rtw8822c.h','BIT_3WIRE_TX_EN'),('rtw8822c.h','BIT_3WIRE_RX_EN'),('rtw8822c.h','BIT_3WIRE_PI_ON'),('rtw8822c.h','REG_ENCCK'),('rtw8822c.h','BIT_CCK_OFDM_BLK_EN')])
declarations='\n'.join(extract(file,name,kind) for file,name,kind in [('main.h','rtw_rf_path','enum'),('main.h','rtw_chip_type','enum'),('main.h','rtw_hci_type','enum'),('main.h','rtw_phy_cond','struct'),('main.h','rtw_phy_cond2','struct'),('phy.c','phy_cfg_pair','struct'),('phy.c','phy_table_tile','union'),('main.h','rtw_table','struct')])
source=(reference/'rtw88/rtw8822c_table.c').read_text();arrays=[];bindings=[]
for name in ['rtw8822c_mac','rtw8822c_bb','rtw8822c_agc','rtw8822c_array_mp_cal_init','rtw8822c_rf_b','rtw8822c_rf_a']:
    match=re.search(r'static const u32 '+name+r'\[\] = \{.*?\n};\s*RTW_DECL[^;]+;',source,re.S);body=match.group();arrays.append(body);manifest.append(dict(path='rtw88/rtw8822c_table.c',symbol=name+' and descriptor',sha256=hashlib.sha256(body.encode()).hexdigest()))
# Reproduce every committed register/condition pair, including currently
# unselected branches, against the pinned licensed driver source.
assert hashlib.sha256(source.encode()).hexdigest()=='ec3f4d9eed016932b9100e4e2332c12f67bd0824a3f3b4b05cc515e7916a2247'
rust=['// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause','// Copyright(c) 2018-2019 Realtek Corporation','// RTL8822C register-initialization values from the licensed driver source.','// Source: Linux a804c5742bff224d4cb4d25dd383554d598be32b rtw88/rtw8822c_table.c.','// Full donor SHA256 ec3f4d9eed016932b9100e4e2332c12f67bd0824a3f3b4b05cc515e7916a2247.','//! RTL8822C register-initialization tables from rtw8822c_table.c.']
for rust_name,name in [('MAC','rtw8822c_mac'),('BB','rtw8822c_bb'),('AGC','rtw8822c_agc'),('CAL','rtw8822c_array_mp_cal_init'),('RF_A','rtw8822c_rf_a'),('RF_B','rtw8822c_rf_b')]:
    match=re.search(r'static const u32 '+name+r'\[\] = \{(.*?)\n};',source,re.S)
    body=re.sub(r'/\*.*?\*/|//[^\n]*','',match.group(1),flags=re.S)
    assert not re.sub(r'0x[0-9a-fA-F]+|[\s,]','',body)
    values=[int(v,16) for v in re.findall('0x[0-9a-fA-F]+',body)]
    assert len(values)%2==0
    pairs=list(zip(values[::2],values[1::2]))
    digest=hashlib.sha256(match.group().encode()).hexdigest()
    rust+=['',f'// {name}: {len(pairs)} complete pairs; source declaration SHA256 {digest}.',f'pub(super) static {rust_name}: &[[u32; 2]] = &[']+[f'    [0x{a:08x}, 0x{v:08x}],' for a,v in pairs]+['];']
generated=out/'data.rs';generated.write_text('\n'.join(rust)+'\n')
subprocess.run(['rustfmt','--edition','2024',str(generated)],check=True)
native=pathlib.Path(__file__).resolve().parents[3]/'stela-driver-net/src/wifi/realtek/phy/data.rs'
assert generated.read_bytes()==native.read_bytes(), 'committed native table bytes differ from complete pinned source export'
manifest.append(dict(native_table_bytes=native.stat().st_size,native_table_sha256=hashlib.sha256(native.read_bytes()).hexdigest(),complete_pairs=46215))
# The RTL8821C's register tables, exported the same way to its own module.
source_8821c=(reference/'rtw88/rtw8821c_table.c').read_text()
assert hashlib.sha256(source_8821c.encode()).hexdigest()=='ebc2547ddd66b7df434e0ef91319eddf5565c452863c4a0fd64660839d3e9a0c'
rust=['// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause','// Copyright(c) 2018-2019 Realtek Corporation','// RTL8821C register-initialization values from the licensed driver source.','// Source: Linux rtw88/rtw8821c_table.c.','// Full donor SHA256 ebc2547ddd66b7df434e0ef91319eddf5565c452863c4a0fd64660839d3e9a0c.','//! RTL8821C register-initialization tables from rtw8821c_table.c.']
pairs_8821c=0
for rust_name,name in [('MAC','rtw8821c_mac'),('AGC','rtw8821c_agc'),('AGC_BTG_TYPE2','rtw8821c_agc_btg_type2'),('BB','rtw8821c_bb'),('RF_A','rtw8821c_rf_a')]:
    match=re.search(r'static const u32 '+name+r'\[\] = \{(.*?)\n};',source_8821c,re.S)
    body=re.sub(r'/\*.*?\*/|//[^\n]*','',match.group(1),flags=re.S)
    assert not re.sub(r'0x[0-9a-fA-F]+|[\s,]','',body)
    values=[int(v,16) for v in re.findall('0x[0-9a-fA-F]+',body)]
    assert len(values)%2==0
    pairs=list(zip(values[::2],values[1::2]));pairs_8821c+=len(pairs)
    digest=hashlib.sha256(match.group().encode()).hexdigest()
    rust+=['',f'// {name}: {len(pairs)} complete pairs; source declaration SHA256 {digest}.',f'pub(super) static {rust_name}: &[[u32; 2]] = &[']+[f'    [0x{a:08x}, 0x{v:08x}],' for a,v in pairs]+['];']
generated=out/'data_8821c.rs';generated.write_text('\n'.join(rust)+'\n')
subprocess.run(['rustfmt','--edition','2024',str(generated)],check=True)
native=pathlib.Path(__file__).resolve().parents[3]/'stela-driver-net/src/wifi/realtek/phy/rtl8821c/data.rs'
assert generated.read_bytes()==native.read_bytes(), 'committed RTL8821C table bytes differ from complete pinned source export'
manifest.append(dict(native_8821c_table_bytes=native.stat().st_size,native_8821c_table_sha256=hashlib.sha256(native.read_bytes()).hexdigest(),complete_8821c_pairs=pairs_8821c))
ph=(reference/'rtw88/phy.h').read_text();table_macros=ph[ph.index('#define RTW_DECL_TABLE_PHY_COND_CORE'):ph.index('#define RTW_DECL_TABLE_BB_PG')]
manifest.append(dict(path='rtw88/phy.h',symbol='source table declaration macros',sha256=hashlib.sha256(table_macros.encode()).hexdigest()))
chip=(reference/'rtw88/rtw8822c.c').read_text();chip_fields=[]
for field in ['rf_base_addr','rf_sipi_addr','mac_tbl','agc_tbl','bb_tbl','rfk_init_tbl','rf_tbl']:
    line=re.search(r'\.'+field+r'\s*=.*?,\n',chip).group().strip();chip_fields.append(line);manifest.append(dict(path='rtw88/rtw8822c.c',symbol=field,sha256=hashlib.sha256(line.encode()).hexdigest()))
assert 'rtw8822c_rf_b_tbl, &rtw8822c_rf_a_tbl' in ''.join(chip_fields)
rfe=re.search(r'static const struct rtw_rfe_def rtw8822c_rfe_defs\[\] = \{.*?\n};',chip,re.S).group();assert len(re.findall(r'RTW_DEF_RFE\(',rfe))==7 and 'RTW_DEF_RFE_EXT' not in rfe
manifest.append(dict(path='rtw88/rtw8822c.c',symbol='source seven RFE definitions',sha256=hashlib.sha256(rfe.encode()).hexdigest()))
helpers='\n'.join(extract('hci.h',n) for n in ['rtw_read32_mask','rtw_write32_mask','rtw_write8_set','rtw_write32_set','rtw_write32_clr','rtw_read_rf','rtw_write_rf'])
rf_functions='\n'.join(extract('phy.c',n) for n in ['rtw_phy_read_rf','rtw_phy_write_rf_reg_sipi','rtw_phy_write_rf_reg','rtw_phy_write_rf_reg_mix'])
condition_functions='\n'.join(extract('phy.c',n) for n in ['rtw_phy_setup_phy_cond','check_positive','rtw_parse_tbl_phy_cond'])
config_functions='\n'.join(extract('phy.c',n) for n in ['rtw_phy_cfg_mac','rtw_phy_cfg_agc','rtw_phy_cfg_bb','rtw_phy_cfg_rf'])
load_functions='\n'.join(extract('phy.c',n) for n in ['rtw_load_rfk_table','rtw_phy_load_tables'])
header_function=extract('rtw8822c.c','rtw8822c_header_file_init');phase_function=extract('rtw8822c.c','rtw8822c_phy_set_param')
load_inline=extract('main.h','rtw_load_table')
preamble=r'''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
static u32 rf_failures;
#define __LITTLE_ENDIAN 1
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define BUILD_BUG_ON(x) _Static_assert(!(x),"source layout")
#define __ffs(x) __builtin_ctz(x)
#define WARN(x,...) do{if(x)abort();}while(0)
#define rtw_err(...) ((void)(rf_failures++))
#define rtw_dbg(...) ((void)0)
#define lockdep_assert_held(x) ((void)(x))
struct rtw_dev;
'''
models=r'''struct rtw_chip_ops {u32(*read_rf)(struct rtw_dev*,enum rtw_rf_path,u32,u32);bool(*write_rf)(struct rtw_dev*,enum rtw_rf_path,u32,u32,u32);};
struct rtw_chip_info {enum rtw_chip_type id;const struct rtw_chip_ops*ops;u32 rf_base_addr[2],rf_sipi_addr[2];const struct rtw_table *mac_tbl,*bb_tbl,*agc_tbl,*rfk_init_tbl,*rf_tbl[2];};
struct rtw_hal {u8 cut_version,rf_phy_num,rf_path_num,antenna_tx,antenna_rx;struct rtw_phy_cond phy_cond;struct rtw_phy_cond2 phy_cond2;};
struct rtw_efuse {u8 crystal_cap,rfe_option,ext_lna_2g,ext_pa_2g,ext_lna_5g,ext_pa_5g,btcoex,alna_type,glna_type,apa_type,gpa_type;};
struct rtw_dpk_info {bool is_dpk_pwr_on;};
struct rtw_dm_info {struct rtw_dpk_info dpk_info;u8 cck_gi_u_bnd,cck_gi_l_bnd;};
struct rtw_dev {const struct rtw_chip_info*chip;struct rtw_hal hal;struct rtw_efuse efuse;struct rtw_dm_info dm_info;int mutex;};
struct rtw_rfe_def {const struct rtw_table*agc_btg_tbl;};
static const struct rtw_rfe_def rfe={0};
static const struct rtw_rfe_def*rtw_get_rfe_def(struct rtw_dev*d){if(d->efuse.rfe_option>6)abort();return &rfe;}
static enum rtw_hci_type rtw_hci_type(struct rtw_dev*d){(void)d;return RTW_HCI_TYPE_PCIE;}
static u8 bytes[0x5000];static FILE*trace;static bool record;static u32 events;
static void event(u32 k,u32 r,u32 width,u32 v){if(!record)return;u32 words[4]={k,r,width,v};if(fwrite(words,16,1,trace)!=1)abort();events++;}
static u8 rtw_read8(struct rtw_dev*d,u32 r){(void)d;event(0,r,1,bytes[r]);return bytes[r];}
static u32 rtw_read32(struct rtw_dev*d,u32 r){(void)d;u32 v;memcpy(&v,bytes+r,4);event(0,r,4,v);return v;}
static void rtw_write8(struct rtw_dev*d,u32 r,u8 v){(void)d;event(1,r,1,v);bytes[r]=v;}
static void rtw_write32(struct rtw_dev*d,u32 r,u32 v){event(1,r,4,v);memcpy(bytes+r,&v,4);for(u32 p=0;p<2;p++)if(r==d->chip->rf_sipi_addr[p]){u32 a=d->chip->rf_base_addr[p]+(((v>>20)&255)*4),old;memcpy(&old,bytes+a,4);old=(old&~0xfffffU)|(v&0xfffff);memcpy(bytes+a,&old,4);}}
static void udelay(u32 us){event(2,0,0,us);}
static void mdelay(u32 ms){udelay(ms*1000);}
static void msleep(u32 ms){udelay(ms*1000);}
static void usleep_range(u32 low,u32 high){(void)high;udelay(low);}
/* Deliberate boundary: all later PHY/TRX/calibration helpers are inert, and
 * their observations are outside this trace. The source function is unchanged. */
static void rtw8822c_config_trx_mode(struct rtw_dev*d,u8 tx,u8 rx,bool two){(void)d;(void)tx;(void)rx;(void)two;record=false;}
static void rtw_phy_init(struct rtw_dev*d){(void)d;}
static void rtw8822c_rf_init(struct rtw_dev*d){(void)d;}
static void rtw8822c_pwrtrack_init(struct rtw_dev*d){(void)d;}
static void rtw_bf_phy_init(struct rtw_dev*d){(void)d;}
'''
main=r'''int main(int argc,char**argv){if(argc!=2)return 2;trace=fopen(argv[1],"wb+");if(!trace)abort();
struct rtw_chip_ops ops={.read_rf=rtw_phy_read_rf,.write_rf=rtw_phy_write_rf_reg_mix};struct rtw_chip_info chip={.id=RTW_CHIP_TYPE_8822C,.ops=&ops,CHIP_FIELDS};
for(u32 cut=0;cut<7;cut++)for(u32 board=0;board<7;board++)for(u32 x=0;x<4;x++){
u32 caps[4]={0,1,63,127};u32 seed=cut*28+board*4+x;for(u32 i=0;i<sizeof(bytes);i++)bytes[i]=(i*13+seed*7)&255;
u32 sys=(1U<<27)|(cut<<12),ready=0xc078;memcpy(bytes+0xf0,&sys,4);memcpy(bytes+0x80,&ready,4);
struct rtw_dev d={.chip=&chip,.hal={.cut_version=cut,.rf_phy_num=2,.rf_path_num=2,.antenna_tx=3,.antenna_rx=3},.efuse={.rfe_option=board,.crystal_cap=caps[x]}};
rtw_phy_setup_phy_cond(&d,0);u32 condition;memcpy(&condition,&d.hal.phy_cond,4);
u32 header[6]={cut,board,caps[x],seed,condition,0};long start=ftell(trace);if(fwrite(header,24,1,trace)!=1)abort();events=0;rf_failures=0;record=true;rtw8822c_phy_set_param(&d);record=false;if(rf_failures)abort();long end=ftell(trace);if(fseek(trace,start+20,SEEK_SET)||fwrite(&events,4,1,trace)!=1||fseek(trace,end,SEEK_SET))abort();if(fwrite(bytes,sizeof(bytes),1,trace)!=1)abort();
}
/* Reproduce the actual source one-PHY inconsistency independently: load
 * chooses B's bound descriptor, helper rejects it, caller ignores false. */
struct rtw_dev one={.chip=&chip,.hal={.cut_version=1,.rf_phy_num=1,.rf_path_num=1},.efuse={.rfe_option=0}};
rtw_phy_setup_phy_cond(&one,0);rf_failures=0;record=false;rtw_phy_load_tables(&one);
u32 unsupported[5]={one.hal.rf_path_num,one.hal.rf_phy_num,chip.rf_tbl[0]==&rtw8822c_rf_b_tbl,chip.rf_tbl[0]->rf_path,rf_failures};if(!rf_failures||fwrite(unsupported,20,1,trace)!=1)abort();
if(fclose(trace))abort();return 0;}
'''
main=main.replace('CHIP_FIELDS',''.join(chip_fields))
source=out/'oracle.c';source.write_text(preamble+macros+'\n'+declarations+'\n'+models+helpers+'\n'+rf_functions+'\n'+load_inline+'\n'+condition_functions+'\n'+config_functions+'\n'+table_macros+'\n'+'\n'.join(arrays)+'\n'+load_functions+'\n'+header_function+'\n'+phase_function+'\n'+main)
exe=out/'oracle';subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(source),'-o',str(exe)],check=True)
trace=out/'trace.bin';subprocess.run([str(exe),str(trace)],check=True)
manifest.append(dict(cases=196,trace_bytes=trace.stat().st_size,trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),boundary='recording ends at actual config_trx_mode call; later functions inert, no calibration proof'))
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest[-1]))

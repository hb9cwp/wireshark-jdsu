/*
 packet-jdsu-frp.c
 Wireshark dissector plugin for Filter Result Packet (FRP) protocol used
 for encapsulation in the PacketPortal system from JDSU

 $Id$

 Copyright 2012, 2013 Rolf Sommerhalder <rolf.sommerhalder@switch.ch>

 skeletton code from
  http://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html
 and
  Section 1.2 "Skeletton Code" in README.developer.html

 see also, notably last two slides
  http://sharkfest.wireshark.org/sharkfest.08/D03_Harris_Writing%20Wireshark%20Dissectors_Advanced.pdf

 for fragment reassembly see also
  Section 2.7 "Reassembly/desegmentation" in README.developer.html
  less ~/node.js/wireshark/epan/reassemble.c
 and
  http://www.wireshark.org/docs/wsdg_html_chunked/ChDissectReassemble.html
  http://anonsvn.wireshark.org/viewvc/trunk/epan/reassemble.h?revision=44802&view=markup
  http://anonsvn.wireshark.org/viewvc/trunk/epan/reassemble.c?revision=45016&view=markup
 P2 (inner, capture payload) over P1 (outer, FRP) over UDP:
  http://anonsvn.wireshark.org/viewvc/trunk/epan/dissectors/packet-rtp.h?revision=43536&view=markup
  http://anonsvn.wireshark.org/viewvc/trunk/epan/dissectors/packet-rtp.c?revision=46292&view=markup
 P2 (inner, capture payload) over P1 (outer, FRP) over TCP:
  packet-tds.c
   http://anonsvn.wireshark.org/viewvc/trunk/epan/dissectors/packet-tds.c?revision=45017&view=markup
  P1= packet-smpp.*
   http://anonsvn.wireshark.org/viewvc/trunk/epan/dissectors/packet-smpp.h?revision=43538&view=markup
   http://anonsvn.wireshark.org/viewvc/trunk/epan/dissectors/packet-smpp.c?revision=45017&view=markup
  P2= packet-gsm_sms_ud.c
   http://anonsvn.wireshark.org/viewvc/trunk/epan/dissectors/packet-gsm_sms_ud.c?revision=45017&view=markup

 for debugging aids see
  http://wiki.wireshark.org/Development/Tips
  http://anonsvn.wireshark.org/viewvc/trunk/epan/proto.h?revision=45884&view=markup

 for adding Layer-2 dissector with register_dissector(), and User Link-Layer Types, see
  http://www.kazimer.com/tutorials/wireshark/ethereal_layer2_pg5.html
  http://wiki.wireshark.org/HowToDissectAnything
  http://ask.wireshark.org/questions/3083/set-dlt_user-in-dissector-registration
  http://ask.wireshark.org/questions/8823/error-in-column-payload-protocol-dissector-not-found

*/

#undef Wireshark19			/* set for Wireshark >= 1.9 */
#undef DEBUG_FRAGMENTS

/*#include <stdio.h>*/

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include "packet-tcp.h"

/*
#define FRP_PORT 4660
#define FRP_PORT 5001
*/
#define FRP_PORTS "4660,5001"

#define FRP_flagA_Reserved	(0x1F<<3)
#define FRP_flagA_Version	(0x07<<0)

#define FRP_flagB_P		(1<<15)
#define FRP_flagB_F		(1<<14)
#define FRP_flagB_T		(1<<13)
#define FRP_flagB_O		(1<<12)
#define FRP_flagB_OP		(1<<11)
#define FRP_flagB_TL		(1<<10)
#define FRP_flagB_HWmajor	(0x07<<7)
#define FRP_flagB_HWminor	(0x7F<<0)

#define FRP_flagC_B		(1<<15)
#define FRP_flagC_S		(1<<14)
#define FRP_flagC_H		(1<<13)
#define FRP_flagC_E		(1<<12)
#define FRP_flagC_R		(1<<11)
#define FRP_flagC_PacketWordLen	(0x7FF<<0)

static int hf_frp_flagA_Reserved = -1;
static int hf_frp_flagA_Version = -1;

static int hf_frp_flagB_P = -1;
static int hf_frp_flagB_F = -1;
static int hf_frp_flagB_T = -1;
static int hf_frp_flagB_O = -1;
static int hf_frp_flagB_OP = -1;
static int hf_frp_flagB_TL = -1;
static int hf_frp_flagB_HWmajor = -1;
static int hf_frp_flagB_HWminor = -1;

static int hf_frp_flagC_B = -1;
static int hf_frp_flagC_S = -1;
static int hf_frp_flagC_H = -1;
static int hf_frp_flagC_E = -1;
static int hf_frp_flagC_R = -1;
static int hf_frp_flagC_PacketWordLen = -1;

static int hf_frp_pdu_type = -1;
static int hf_frp_flag_a = -1;
static int hf_frp_probe_id = -1;
static int hf_frp_flag_b = -1;
static int hf_frp_time_s = -1;
static int hf_frp_time_ns = -1;
static int hf_frp_time = -1;
static int hf_frp_reserved = -1;
static int hf_frp_injected = -1;
static int hf_frp_flag_c = -1;
static int hf_frp_matched = -1;
static int hf_frp_congested = -1;
static int hf_frp_sequence = -1;
static int hf_frp_frag_len = -1;

static int proto_frp = -1;

static gint ett_frp = -1;
static gint ett_frp_Flag = -1;
static dissector_handle_t eth_handle;

static const value_string packettypenames[] = {
    { 0xed, "FRP from PRE" },
    { 0xef, "FRP from SFProbe" },
    { 0, NULL }
};

/* Added to be able to configure FRP ports */
static range_t *global_frp_tcp_ports, *global_frp_udp_ports;
static dissector_handle_t frp_tcp_handle, frp_udp_handle;

/* defragmention of FRP */
static gboolean frp_defragment = TRUE;

static GHashTable *frp_fragment_table = NULL;
static GHashTable *frp_reassembled_table = NULL;

static gint ett_frp_fragment = -1;
static gint ett_frp_fragments = -1;

static int hf_frp_fragments = -1;
static int hf_frp_fragment = -1;
static int hf_frp_fragment_overlap = -1;
static int hf_frp_fragment_overlap_conflicts = -1;
static int hf_frp_fragment_multiple_tails = -1;
static int hf_frp_fragment_too_long_fragment = -1;
static int hf_frp_fragment_error = -1;
static int hf_frp_fragment_count = -1;
static int hf_frp_reassembled_in = -1;
static int hf_frp_reassembled_length = -1;
/*static int hf_frp_reassembled_data = -1;*/

static const fragment_items frp_frag_items = {
 /* Fragment subtrees */
 &ett_frp_fragment,
 &ett_frp_fragments,
 /* Fragment fields */
 &hf_frp_fragments,
 &hf_frp_fragment,
 &hf_frp_fragment_overlap,
 &hf_frp_fragment_overlap_conflicts,
 &hf_frp_fragment_multiple_tails,
 &hf_frp_fragment_too_long_fragment,
 &hf_frp_fragment_error,
 &hf_frp_fragment_count,
 /* Reassembled fields */
 &hf_frp_reassembled_in,
 &hf_frp_reassembled_length,
 #ifdef Wireshark19
  NULL,  /*&hf_frp_reassembled_data,*/
 #endif
 "FRP fragments"  /* Tag */
};


static guint8 flagA, type;
static guint16 flagB, flagC;
static int headerLen= 0;
static int payloadLen= 0;
static int PL= 0; /* FRP packet length (in bytes) from outer TCP or UDP header */
static int FL= 0; /* if (F ==1) then fragmented payload length (in words) *2 (in bytes) */
static int realPWL= 0; /* real packet length (in words) */
static guint32 seqNr= 0;


static void frp_frag_init(void) {
 fragment_table_init(&frp_fragment_table);
 reassembled_table_init(&frp_reassembled_table);
}

static int decode_frp_header(tvbuff_t *tvb) {
 PL= tvb_length(tvb);
 if (PL <40) return 0;  /* check packet is longer than FRP header */

 type= tvb_get_guint8(tvb, 0);
 flagA= tvb_get_guint8(tvb, 1);
 flagB= tvb_get_ntohs(tvb, 8);
 flagC= tvb_get_ntohs(tvb, 26);

 /* check type if it's an FRP, either FRP feed from PRE, or FRPs from SFProbes to PRE */
 if (!( ((type == 0xED) && (flagA == 0x01))
       ||
        ((type == 0xEF) && (flagA == 0xEF))
    ) ) return 0;

 realPWL= flagC & FRP_flagC_PacketWordLen;
 seqNr= tvb_get_ntohl(tvb, 36);

 /* work out header length, e.g. payload start */
 if (flagB & FRP_flagB_F) {  /* remaining fragmented part 2/2 */
  headerLen= 42;
  if (PL <42) return 0;
  FL= tvb_get_ntohs(tvb, 40) *2;
  if (flagB & FRP_flagB_O) {
   if ((realPWL >0) && (realPWL < (FL+PL)/2 )) {
    payloadLen= FL -1;
   } else {
    payloadLen= FL;
   }
  } else {
   payloadLen= FL;
  }
 } else {  /* flagB_F == 0 */
  headerLen= 40;
  if (flagB & FRP_flagB_T) {  /* fragmented part 1/2 */
   payloadLen= PL -42;
  } else {  /* not fragmented */
   if (flagB & FRP_flagB_O) {
    if ((realPWL >0) && (realPWL < PL/2)) {
     payloadLen= PL -43;
    } else {
     payloadLen= PL -42;
    }
   } else {
    payloadLen= PL -42;
   }
  }
 }
 return payloadLen;
}


static int dissect_frp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean is_tcp _U_) {
 int offset= 0;
 tvbuff_t      *next_tvb;

 if (tree) { /* we are being asked for details */
  proto_item *ti = NULL, *tf= NULL;
  proto_tree *frp_tree = NULL, *field_tree= NULL;

  ti = proto_tree_add_item(tree, proto_frp, tvb, 0, headerLen, ENC_NA);
  frp_tree = proto_item_add_subtree(ti, ett_frp);

  proto_tree_add_item(frp_tree, hf_frp_pdu_type, tvb, 0, 1, ENC_BIG_ENDIAN);
  offset += 1;
  tf= proto_tree_add_item(frp_tree, hf_frp_flag_a, tvb, offset, 1, ENC_BIG_ENDIAN);
  field_tree = proto_item_add_subtree(tf, ett_frp_Flag);
  proto_tree_add_item(field_tree, hf_frp_flagA_Reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(field_tree, hf_frp_flagA_Version, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(frp_tree, hf_frp_probe_id, tvb, offset, 6, ENC_BIG_ENDIAN);
  offset += 6;
  tf= proto_tree_add_item(frp_tree, hf_frp_flag_b, tvb, offset, 2, ENC_BIG_ENDIAN);
  field_tree = proto_item_add_subtree(tf, ett_frp_Flag);
  proto_tree_add_item(field_tree, hf_frp_flagB_P, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(field_tree, hf_frp_flagB_F, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(field_tree, hf_frp_flagB_T, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(field_tree, hf_frp_flagB_O, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(field_tree, hf_frp_flagB_OP, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(field_tree, hf_frp_flagB_TL, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(field_tree, hf_frp_flagB_HWmajor, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(field_tree, hf_frp_flagB_HWminor, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(frp_tree, hf_frp_time_s, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(frp_tree, hf_frp_time_ns, tvb, offset, 4, ENC_BIG_ENDIAN);
  /*offset += 4;*/  offset -= 4;
  proto_tree_add_item(frp_tree, hf_frp_time, tvb, offset, 8, ENC_BIG_ENDIAN);
  offset += 8;
  proto_tree_add_item(frp_tree, hf_frp_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(frp_tree, hf_frp_injected, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  tf= proto_tree_add_item(frp_tree, hf_frp_flag_c, tvb, offset, 2, ENC_BIG_ENDIAN);
  field_tree = proto_item_add_subtree(tf, ett_frp_Flag);
  proto_tree_add_item(field_tree, hf_frp_flagC_B, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(field_tree, hf_frp_flagC_S, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(field_tree, hf_frp_flagC_H, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(field_tree, hf_frp_flagC_E, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(field_tree, hf_frp_flagC_R, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(field_tree, hf_frp_flagC_PacketWordLen, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(frp_tree, hf_frp_matched, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(frp_tree, hf_frp_congested, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(frp_tree, hf_frp_sequence, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  if (headerLen == 42) {
   proto_tree_add_item(frp_tree, hf_frp_frag_len, tvb, offset, 2, ENC_BIG_ENDIAN);
   offset += 2;
  }
  #ifdef DEBUG_FRAGMENTS
   proto_tree_add_debug_text(tree, "pass_dissect_common= %d", pass_dissect_common++);
   proto_tree_add_debug_text(tree, "headerLen= %d  payloadLen= %d", headerLen, payloadLen);
  #endif
 }
 next_tvb = tvb_new_subset_remaining(tvb, headerLen);
 call_dissector(eth_handle, next_tvb, pinfo, tree);

 /* return (headerLen + payloadLen) */
 return tvb_length(tvb);
}


#ifdef Wireshark19
static int dissect_frp_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
#else
static int dissect_frp_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
#endif
 int offset= 0;

 if (!decode_frp_header(tvb)) return 0;  /* check if FRP */
 col_set_str(pinfo->cinfo, COL_PROTOCOL, "FRP");
 col_clear(pinfo->cinfo,COL_INFO);

 if (frp_defragment && ((flagB & FRP_flagB_T) || (flagB & FRP_flagB_F))) { /* fragments to reassemble */
  tvbuff_t* new_tvb= NULL;
  fragment_data *fd= NULL;
  pinfo->fragmented= TRUE;
  offset= (flagB & FRP_flagB_T) ? 40 : 42;
  fd= fragment_add_seq_check(tvb, offset, pinfo,
   seqNr,  /* ID of fragments belonging together */
   frp_fragment_table,  /* list of message fragments */
   frp_reassembled_table,  /* list of reassembled messages */
   (flagB & FRP_flagB_T) ? 0 : 1,  /* fragment sequence number */
   /*tvb_length_remaining(tvb, offset),*/  /* fragment length - to the end */
   payloadLen,
   (flagB & FRP_flagB_F) ? FALSE : TRUE);  /* more fragments? */
  if (fd) {  /* reassembled */
   col_append_fstr(pinfo->cinfo, COL_INFO, " [FRP reassembled in %u]", fd->reassembled_in);
  } else {  /* not last packet of reassembled short message */
   col_append_fstr(pinfo->cinfo, COL_INFO, " [FRP fragment %u]", (flagB & FRP_flagB_T) ? 0 : 1);
  }
  new_tvb= process_reassembled_data(tvb, offset, pinfo,
   "Reassembled FRP", fd, &frp_frag_items, NULL, tree);
  if (new_tvb) {  /* defragmented data with payload */
   pinfo->fragmented= FALSE;
   call_dissector(eth_handle, new_tvb, pinfo, tree);
   return tvb_length(new_tvb);
  } else {  /* new subset with payload */
   #undef DissectFirstFragment
   #ifdef DissectFirstFragment  /* breaks dissection after reassembly of TCP */
   if (flagB & FRP_flagB_T)  /* dissect first fragment only */
    return dissect_frp_common(tvb, pinfo, tree, FALSE);
   else
    return 0;
   #else
   return 0;  /* do not attempt to dissect fragments */
   #endif
  }
 } else { /* not fragmented, new subset with payload */
  return dissect_frp_common(tvb, pinfo, tree, FALSE);
 }
}


static int initialOffset= 8;

static guint get_frp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset) {
 tvbuff_t *next_tvb;

 /*next_tvb= tvb_new_subset_remaining(tvb, offset);*/
 next_tvb= tvb_new_subset_remaining(tvb, offset +initialOffset);  initialOffset= 0;
 if (!decode_frp_header(next_tvb)) return 0;
 /*return headerLen +payloadLen;*/
 return payloadLen -(42 -headerLen);  /* compensate the 42 Bytes already in buffer */
}

static void dissect_frp_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
 col_set_str(pinfo->cinfo, COL_PROTOCOL, "FRP");
 col_clear(pinfo->cinfo,COL_INFO);
 dissect_frp_common(tvb, pinfo, tree, TRUE);
}

#ifdef Wireshark19
static int dissect_frp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
#else
static int dissect_frp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
#endif
 tcp_dissect_pdus(tvb, pinfo, tree, frp_defragment, 42, get_frp_pdu_len, dissect_frp_tcp_pdu);
 return 1;
}


static void tcp_add_callback(guint32 port) {
  dissector_add_uint("tcp.port", port, frp_tcp_handle);
}

static void udp_add_callback(guint32 port) {
  dissector_add_uint("udp.port", port, frp_udp_handle);
}

static void tcp_delete_callback(guint32 port) {
  dissector_add_uint("tcp.port", port, frp_tcp_handle);
}

static void udp_delete_callback(guint32 port) {
  dissector_add_uint("udp.port", port, frp_udp_handle);
}

void proto_reg_handoff_frp(void) {
 static range_t *frp_tcp_ports, *frp_udp_ports;
 static gboolean Initialized= FALSE;

 if (!Initialized) {
  frp_tcp_handle = new_create_dissector_handle(dissect_frp_tcp, proto_frp);
  frp_udp_handle = new_create_dissector_handle(dissect_frp_udp, proto_frp);
  Initialized= TRUE;
 } else {
  range_foreach(frp_tcp_ports, tcp_delete_callback);
  range_foreach(frp_udp_ports, udp_delete_callback);
  g_free(frp_tcp_ports);
  g_free(frp_udp_ports);
 }
 frp_tcp_ports = range_copy(global_frp_tcp_ports);
 frp_udp_ports = range_copy(global_frp_udp_ports);
 range_foreach(frp_tcp_ports, tcp_add_callback);
 range_foreach(frp_udp_ports, udp_add_callback);

 eth_handle= find_dissector("eth");
}


static const true_false_string tfs_flagB_P = {
 "captured on Fiber side",
 "captured on Copper side"
};

void proto_register_frp(void) {

 static hf_register_info hf[] = {
  {&hf_frp_pdu_type,
   {"Type", "frp.type",
    FT_UINT8, BASE_HEX, VALS(packettypenames), 0x0, NULL, HFILL}},
  {&hf_frp_flag_a,
   {"Flag A", "frp.flagA",
    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
  {&hf_frp_flagA_Reserved,
   {"Reserved", "frp.flagA.Reserved",
    FT_UINT8, BASE_HEX, NULL, FRP_flagA_Reserved, NULL, HFILL}},
  {&hf_frp_flagA_Version,
   {"Version", "frp.flagA.Version",
    FT_UINT8, BASE_DEC, NULL, FRP_flagA_Version, NULL, HFILL}},
  {&hf_frp_probe_id,
   {"Probe ID", "frp.probeID",
    /*FT_UINT64, BASE_HEX,*/
    FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},
  {&hf_frp_flag_b,
   {"Flag B", "frp.flagB",
    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
  {&hf_frp_flagB_P,
   {"P: Packet on fiber side", "frp.flagB.P",
    FT_BOOLEAN, 16, TFS(&tfs_flagB_P), FRP_flagB_P, NULL, HFILL}},
  {&hf_frp_flagB_F,
   {"F: Fragmented part (2/2)", "frp.flagB.F",
    FT_BOOLEAN, 16, NULL, FRP_flagB_F, NULL, HFILL}},
  {&hf_frp_flagB_T,
   {"T: Truncated part (1/2)", "frp.flagB.T",
    FT_BOOLEAN, 16, NULL, FRP_flagB_T, NULL, HFILL}},
  {&hf_frp_flagB_O,
   {"O: One byte less in packet length", "frp.flagB.O",
    FT_BOOLEAN, 16, NULL, FRP_flagB_O, NULL, HFILL}},
  {&hf_frp_flagB_OP,
   {"OP: Packet injected on fiber", "frp.flagB.OP",
    FT_BOOLEAN, 16, NULL, FRP_flagB_OP, NULL, HFILL}},
  {&hf_frp_flagB_TL,
   {"TL: Timing Lock", "frp.flagB.TL",
    FT_BOOLEAN, 16, NULL, FRP_flagB_TL, NULL, HFILL}},
  {&hf_frp_flagB_HWmajor,
   {"HW Major", "frp.flagB.HWmajor",
    FT_UINT16, BASE_DEC, NULL, FRP_flagB_HWmajor, NULL, HFILL}},
  {&hf_frp_flagB_HWminor,
   {"HW minor", "frp.flagB.HWminor",
    FT_UINT16, BASE_DEC, NULL, FRP_flagB_HWminor, NULL, HFILL}},
  {&hf_frp_time_s,
   {"Timestamp sec", "frp.time_s",
    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
  {&hf_frp_time_ns,
   {"Timestamp nsec", "frp.time_ns",
    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
  {&hf_frp_time,
   {"Timestamp", "frp.time",
    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL}},
  {&hf_frp_reserved,
   {"Reserved", "frp.reserved",
    FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
  {&hf_frp_injected,
   {"Injected Count", "frp.injected",
    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
  {&hf_frp_flag_c,
   {"Flag C", "frp.flag_c",
    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
  {&hf_frp_flagC_B,
   {"B: Bad FCS", "frp.flagC.B",
    FT_BOOLEAN, 16, NULL, FRP_flagC_B, NULL, HFILL}},
  {&hf_frp_flagC_S,
   {"S: Slice payload", "frp.flagC.S",
    FT_BOOLEAN, 16, NULL, FRP_flagC_S, NULL, HFILL}},
  {&hf_frp_flagC_H,
   {"H: Headers only", "frp.flagC.H",
    FT_BOOLEAN, 16, NULL, FRP_flagC_H, NULL, HFILL}},
  {&hf_frp_flagC_E,
   {"E: Encrypted", "frp.flagC.E",
    FT_BOOLEAN, 16, NULL, FRP_flagC_E, NULL, HFILL}},
  {&hf_frp_flagC_R,
   {"R: all FRPs Routed to this port", "frp.flagC.R",
    FT_BOOLEAN, 16, NULL, FRP_flagC_R, NULL, HFILL}},
  {&hf_frp_flagC_PacketWordLen,
   {"PacketWordLen", "frp.flagC.PacketWordLen",
    FT_UINT16, BASE_DEC, NULL, FRP_flagC_PacketWordLen, NULL, HFILL}},
  {&hf_frp_matched,
   {"Matched Bits", "frp.matched",
    FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
  {&hf_frp_congested,
   {"Congestion Count", "frp.congested",
    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
  {&hf_frp_sequence,
   {"Sequence Number", "frp.sequence",
    /*FT_FRAMENUM, BASE_NONE,*/
    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
  {&hf_frp_frag_len,
   {"Fragment Length", "frp.frag_len",
    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},

  {&hf_frp_fragments,
   {"FRP fragments", "frp.fragments",
   FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}},
  {&hf_frp_fragment,
   {"FRP fragment", "frp.fragment",
   FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL}},
  {&hf_frp_fragment_overlap,
   {"FRP fragment overlap", "frp.fragment.overlap",
   FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL}},
  {&hf_frp_fragment_overlap_conflicts,
   {"FRP fragment overlapping with conflicting data",
   "frp.fragment.overlap.conflicts",
   FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL}},
  {&hf_frp_fragment_multiple_tails,
   {"FRP has multiple tail fragments",
   "frp.fragment.multiple_tails",
   FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL}},
  {&hf_frp_fragment_too_long_fragment,
   {"FRP fragment too long", "frp.fragment.too_long_fragment",
   FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL}},
  {&hf_frp_fragment_error,
   {"FRP defragmentation error", "frp.fragment.error",
   FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL}},
  {&hf_frp_fragment_count,
   {"FRP fragment count", "frp.fragment.count",
   FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}},
  {&hf_frp_reassembled_in,
   {"Reassembled in", "frp.reassembled.in",
   FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL}},
  {&hf_frp_reassembled_length,
   {"Reassembled length", "frp.reassembled.length",
   FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL}}
 };

 /* Setup protocol subtree array */
 static gint *ett[] = {
  &ett_frp,
  &ett_frp_Flag,
  &ett_frp_fragment,
  &ett_frp_fragments
 };

 module_t *frp_module;

 proto_frp = proto_register_protocol ("JDSU Filter Result Packet", "FRP", "frp");
 proto_register_field_array(proto_frp, hf, array_length(hf));
 proto_register_subtree_array(ett, array_length(ett));
 /* add FRP to Layer 2 protocol dissectors */
 register_dissector("frp", (dissector_t) dissect_frp_udp, proto_frp);

 frp_module = prefs_register_protocol(proto_frp, proto_reg_handoff_frp);
 range_convert_str(&global_frp_tcp_ports, FRP_PORTS, MAX_TCP_PORT);
 range_convert_str(&global_frp_udp_ports, FRP_PORTS, MAX_UDP_PORT);
 prefs_register_range_preference(frp_module, "tcp.ports", "FRP TCP ports",
  "TCP ports to be decoded as FRP (default: " FRP_PORTS ")",
  &global_frp_tcp_ports, MAX_TCP_PORT);
 prefs_register_range_preference(frp_module, "udp.ports", "FRP UDP Ports",
  "UDP ports to be decoded as FRP (default: " FRP_PORTS ")",
  &global_frp_udp_ports, MAX_UDP_PORT);
 prefs_register_bool_preference(frp_module, "defragment_frp_messages",
  "Reassemble FRP messages",
  "Whether the FRP dissector should reassemble fragments."
  " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
  &frp_defragment);

 register_init_routine(frp_frag_init);  /* initialise reassembly for UDP */
}

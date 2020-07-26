/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2020 Soeren Apel <soeren@apelpie.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "input/lecroy_waveform"

#define CHUNK_SIZE        (4 * 1024 * 1024)
#define CHUNK_FLOAT_COUNT (CHUNK_SIZE / sizeof(float))
#define MAX_CHANNEL_COUNT (4)

struct context {
	gboolean meta_sent;
	gboolean header_read, waveform_read, trigger_sent;
	uint8_t channel_count, current_channel_id;
	struct sr_channel *channels[MAX_CHANNEL_COUNT];
	float out_buf[CHUNK_FLOAT_COUNT];
	uint32_t out_count;

	uint32_t header_size;
	gboolean uses_little_endian, uses_words;
	int32_t wave_descriptor_len, user_text_len, trig_time_array_len, wave_array_len;
	float vertical_gain, vertical_offset, horiz_interval;
	double horiz_offset;

	double samplerate;
};

static int process_header(GString *buf, struct context *inc);
static void create_channels(struct sr_input *in);


static int init(struct sr_input *in, GHashTable *options)
{
	struct context *inc;

	(void)options;

	in->sdi = g_malloc0(sizeof(struct sr_dev_inst));
	in->priv = g_malloc0(sizeof(struct context));

	inc = in->priv;

	/* TOOD: Get input file name */
	/* TODO: Check existance of other input files for other channels */
	/* TODO: Determine number of channels */
	inc->channel_count = 1;
	inc->current_channel_id = 0;

	create_channels(in);

	return SR_OK;
}

static int format_match(GHashTable *metadata, unsigned int *confidence)
{
	(void)metadata;

	/* TODO: Format recognition */

	*confidence = 0;

	return SR_ERR_NA;
}

static int process_header(GString *buf, struct context *inc)
{
	char *hdr;
	char *s;
	gboolean header_valid;

	/*
	 * Note: The routine is called from different contexts. Either
	 * to auto-detect the file format (format_match(), 'inc' is NULL),
	 * or to process the data during acquisition (receive(), 'inc'
	 * is a valid pointer). This header parse routine shall gracefully
	 * deal with unexpected or incorrect input data.
	 */

	/*
	 * File header:
	 *     SCPI block length indicator ("#xxxxxxxxxx")
	 * 000 block descriptor name ("WAVEDESC")
	 * 016 template name (e.g. "LECROY_2_3")
	 * 032 comm_type (0=byte, 1=word)
	 * 034 comm_order (0=MSB first, 1=LSB first)
	 * 036 wave_descriptor_len
	 * 040 user_text_len
	 * 044 reserved
	 * 048 trig_time_array_len
	 * 052 ris_time_array_len
	 * 056 reserved
	 * 060 wave_array_len
	 * 064 wave2_array_len
	 * ...
	 * 096 trace_label
	 * 156 vertical_gain
	 * 160 vertical_offset
	 * 176 horiz_interval (i.e. 1/sampling_freq)
	 * 180 horiz_offset
	 */

	/* Skip SCPI block length indicator if present */
	hdr = (buf->str[0] == '#') ? &(buf->str[11]) : buf->str;
	inc->header_size = (buf->str[0] == '#') ? 11 : 0;

	s = g_strndup(hdr, 8);
	header_valid = g_strcmp0(s, "WAVEDESC") == 0;
	g_free(s);

	if (!header_valid)
		return SR_ERR_DATA;

	/* Stop processing the header if we just want to identify the file. */
	if (!inc)
		return SR_OK;

	inc->uses_words         = (R8(hdr + 32) == 1);
	inc->uses_little_endian = (R8(hdr + 34) == 1);

	if (inc->uses_little_endian) {
		inc->wave_descriptor_len = RL32(hdr + 36);
		inc->user_text_len       = RL32(hdr + 40);
		inc->trig_time_array_len = RL32(hdr + 48);
		inc->wave_array_len      = RL32(hdr + 60);
		inc->vertical_gain       = RLFL(hdr + 156);
		inc->vertical_offset     = RLFL(hdr + 160);
		inc->horiz_interval      = RLFL(hdr + 176);
		inc->horiz_offset        = RLDB(hdr + 180);
	} else {
		inc->wave_descriptor_len = RB32(hdr + 36);
		inc->user_text_len       = RB32(hdr + 40);
		inc->trig_time_array_len = RB32(hdr + 48);
		inc->wave_array_len      = RB32(hdr + 60);
		inc->vertical_gain       = RBFL(hdr + 156);
		inc->vertical_offset     = RBFL(hdr + 160);
		inc->horiz_interval      = RBFL(hdr + 176);
		inc->horiz_offset        = (double)RB64(hdr + 180);
	}

	sr_info("wave_descriptor_len: %d", inc->wave_descriptor_len);
	sr_info("user_text_len:       %d", inc->user_text_len);
	sr_info("trig_time_array_len: %d", inc->trig_time_array_len);
	sr_info("wave_array_len:      %d", inc->wave_array_len);
	sr_info("vertical_gain:       %f", inc->vertical_gain);
	sr_info("vertical_offset:     %f", inc->vertical_offset);
	sr_info("horizontal_interval: %f", inc->horiz_interval);
	sr_info("horizontal_offset:   %f", inc->horiz_offset);

	inc->samplerate = 1.0 / inc->horiz_interval;
	sr_info("Samplerate is %lf Hz", inc->samplerate);

	/* The next read must find waveform data, so let's skip all other stuff */
	inc->header_size +=
		inc->wave_descriptor_len + inc->user_text_len + inc->trig_time_array_len;

	inc->header_read = TRUE;

	return SR_OK;
}

static void create_channels(struct sr_input *in)
{
	struct context *inc;
	int channel;
	char name[8];

	inc = in->priv;

	for (channel = 0; channel < inc->channel_count; channel++) {
		snprintf(name, sizeof(name), "CH%d", channel + 1);
		inc->channels[channel] =
			sr_channel_new(in->sdi, channel, SR_CHANNEL_ANALOG, TRUE, name);
	}
}

static void send_metadata(struct sr_input *in)
{
	struct sr_datafeed_packet packet;
	struct sr_datafeed_meta meta;
	struct sr_config *src;
	struct context *inc;

	inc = in->priv;

	packet.type = SR_DF_META;
	packet.payload = &meta;
	src = sr_config_new(SR_CONF_SAMPLERATE, g_variant_new_uint64(inc->samplerate));
	meta.config = g_slist_append(NULL, src);
	sr_session_send(in->sdi, &packet);
	g_slist_free(meta.config);
	sr_config_free(src);

	inc->meta_sent = TRUE;
}

static void flush_output_buffer(struct sr_input *in)
{
	struct context *inc;
	struct sr_channel *ch;
	struct sr_datafeed_packet packet;
	struct sr_analog_encoding encoding;
	struct sr_analog_meaning meaning;
	struct sr_analog_spec spec;
	struct sr_datafeed_analog analog;

	inc = in->priv;

	ch = inc->channels[inc->current_channel_id];

	if (inc->out_count > 0) {
		sr_analog_init(&analog, &encoding, &meaning, &spec, 2);
		analog.meaning->channels = g_slist_append(NULL, ch);
		analog.num_samples = inc->out_count;
		analog.data = inc->out_buf;
		analog.meaning->mq = SR_MQ_VOLTAGE;
		analog.meaning->unit = SR_UNIT_VOLT;
		analog.meaning->mqflags = 0;
		packet.type = SR_DF_ANALOG;
		packet.payload = &analog;
		sr_session_send(in->sdi, &packet);
		g_slist_free(analog.meaning->channels);

		inc->out_count = 0;
	}
}

static uint32_t process_waveform(struct sr_input *in)
{
	struct context *inc;
	unsigned int bytes_read;
	float value;

	inc = in->priv;
	bytes_read = 0;

	if (inc->uses_words) {
		int16_t raw_value;
		for (uint32_t i = 0; i < in->buf->len / 2; i += 2) {
			if (inc->uses_little_endian)
				raw_value = RL16S(in->buf->str + i);
			else
				raw_value = RB16S(in->buf->str + i);

			value = raw_value * inc->vertical_gain - inc->vertical_offset;

			inc->out_buf[inc->out_count] = value;
			inc->out_count++;
			bytes_read += 2;

			if (inc->out_count == CHUNK_FLOAT_COUNT)
				flush_output_buffer(in);
		}
	} else {
		int8_t raw_value;
		for (uint32_t i = 0; i < in->buf->len; i++) {
			raw_value = R8S(in->buf->str + i);
			value = raw_value * inc->vertical_gain - inc->vertical_offset;

			inc->out_buf[inc->out_count] = value;
			inc->out_count++;
			bytes_read++;

			if (inc->out_count == CHUNK_FLOAT_COUNT)
				flush_output_buffer(in);
		}
	}

	return bytes_read;
}

static int process_buffer(struct sr_input *in)
{
	struct context *inc;
	int res;

	inc = in->priv;

	if (!inc->header_read) {
		res = process_header(in->buf, inc);
		g_string_erase(in->buf, 0, inc->header_size);
		if (res != SR_OK)
			return res;
	}

	if (!inc->meta_sent) {
		std_session_send_df_header(in->sdi);
		send_metadata(in);
	}

	if (!inc->waveform_read)
		g_string_erase(in->buf, 0, process_waveform(in));

	return SR_OK;
}

static int receive(struct sr_input *in, GString *buf)
{
	g_string_append_len(in->buf, buf->str, buf->len);

	if (!in->sdi_ready) {
		/* sdi is ready, notify frontend. */
		in->sdi_ready = TRUE;
		return SR_OK;
	}

	return process_buffer(in);
}

static int end(struct sr_input *in)
{
	struct context *inc;
	int ret;

	inc = in->priv;

	if (in->sdi_ready)
		ret = process_buffer(in);
	else
		ret = SR_OK;

	flush_output_buffer(in);

	if (inc->meta_sent)
		std_session_send_df_end(in->sdi);

	return ret;
}

static int reset(struct sr_input *in)
{
	struct context *inc = in->priv;

	inc->meta_sent = FALSE;
	inc->header_read = FALSE;
	inc->waveform_read = FALSE;
	inc->trigger_sent = FALSE;

	g_string_truncate(in->buf, 0);

	return SR_OK;
}

SR_PRIV struct sr_input_module input_lecroy_waveform = {
	.id = "lecroy_waveform",
	.name = "LeCroy Waveform",
	.desc = "LeCroy Waveform data",
	.exts = (const char*[]){"trc", NULL},
	.options = NULL,
	.metadata = { SR_INPUT_META_HEADER | SR_INPUT_META_REQUIRED },
	.format_match = format_match,
	.init = init,
	.receive = receive,
	.end = end,
	.reset = reset,
};

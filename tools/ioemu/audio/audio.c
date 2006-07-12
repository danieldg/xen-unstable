/*
 * QEMU Audio subsystem
 *
 * Copyright (c) 2003-2005 Vassili Karpov (malc)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "vl.h"

#define AUDIO_CAP "audio"
#include "audio_int.h"

/* #define DEBUG_PLIVE */
/* #define DEBUG_LIVE */
/* #define DEBUG_OUT */

#define SW_NAME(sw) (sw)->name ? (sw)->name : "unknown"

static struct audio_driver *drvtab[] = {
#ifdef CONFIG_OSS
    &oss_audio_driver,
#endif
#ifdef CONFIG_ALSA
    &alsa_audio_driver,
#endif
#ifdef CONFIG_COREAUDIO
    &coreaudio_audio_driver,
#endif
#ifdef CONFIG_DSOUND
    &dsound_audio_driver,
#endif
#ifdef CONFIG_FMOD
    &fmod_audio_driver,
#endif
#ifdef CONFIG_SDL
    &sdl_audio_driver,
#endif
    &no_audio_driver,
    &wav_audio_driver
};

struct fixed_settings {
    int enabled;
    int nb_voices;
    int greedy;
    audsettings_t settings;
};

static struct {
    struct fixed_settings fixed_out;
    struct fixed_settings fixed_in;
    union {
        int hz;
        int64_t ticks;
    } period;
    int plive;
    int log_to_monitor;
} conf = {
    {                           /* DAC fixed settings */
        1,                      /* enabled */
        1,                      /* nb_voices */
        1,                      /* greedy */
        {
            44100,              /* freq */
            2,                  /* nchannels */
            AUD_FMT_S16         /* fmt */
        }
    },

    {                           /* ADC fixed settings */
        1,                      /* enabled */
        1,                      /* nb_voices */
        1,                      /* greedy */
        {
            44100,              /* freq */
            2,                  /* nchannels */
            AUD_FMT_S16         /* fmt */
        }
    },

    { 0 },                      /* period */
    0,                          /* plive */
    0                           /* log_to_monitor */
};

static AudioState glob_audio_state;

volume_t nominal_volume = {
    0,
#ifdef FLOAT_MIXENG
    1.0,
    1.0
#else
    UINT_MAX,
    UINT_MAX
#endif
};

/* http://www.df.lth.se/~john_e/gems/gem002d.html */
/* http://www.multi-platforms.com/Tips/PopCount.htm */
uint32_t popcount (uint32_t u)
{
    u = ((u&0x55555555) + ((u>>1)&0x55555555));
    u = ((u&0x33333333) + ((u>>2)&0x33333333));
    u = ((u&0x0f0f0f0f) + ((u>>4)&0x0f0f0f0f));
    u = ((u&0x00ff00ff) + ((u>>8)&0x00ff00ff));
    u = ( u&0x0000ffff) + (u>>16);
    return u;
}

inline uint32_t lsbindex (uint32_t u)
{
    return popcount ((u&-u)-1);
}

#ifdef AUDIO_IS_FLAWLESS_AND_NO_CHECKS_ARE_REQURIED
#error No its not
#else
int audio_bug (const char *funcname, int cond)
{
    if (cond) {
        static int shown;

        AUD_log (NULL, "Error a bug that was just triggered in %s\n", funcname);
        if (!shown) {
            shown = 1;
            AUD_log (NULL, "Save all your work and restart without audio\n");
            AUD_log (NULL, "Please send bug report to malc@pulsesoft.com\n");
            AUD_log (NULL, "I am sorry\n");
        }
        AUD_log (NULL, "Context:\n");

#if defined AUDIO_BREAKPOINT_ON_BUG
#  if defined HOST_I386
#    if defined __GNUC__
        __asm__ ("int3");
#    elif defined _MSC_VER
        _asm _emit 0xcc;
#    else
        abort ();
#    endif
#  else
        abort ();
#  endif
#endif
    }

    return cond;
}
#endif

void *audio_calloc (const char *funcname, int nmemb, size_t size)
{
    int cond;
    size_t len;

    len = nmemb * size;
    cond = !nmemb || !size;
    cond |= nmemb < 0;
    cond |= len < size;

    if (audio_bug ("audio_calloc", cond)) {
        AUD_log (NULL, "%s passed invalid arguments to audio_calloc\n",
                 funcname);
        AUD_log (NULL, "nmemb=%d size=%zu (len=%zu)\n", nmemb, size, len);
        return NULL;
    }

    return qemu_mallocz (len);
}

static char *audio_alloc_prefix (const char *s)
{
    const char qemu_prefix[] = "QEMU_";
    size_t len;
    char *r;

    if (!s) {
        return NULL;
    }

    len = strlen (s);
    r = qemu_malloc (len + sizeof (qemu_prefix));

    if (r) {
        size_t i;
        char *u = r + sizeof (qemu_prefix) - 1;

        strcpy (r, qemu_prefix);
        strcat (r, s);

        for (i = 0; i < len; ++i) {
            u[i] = toupper (u[i]);
        }
    }
    return r;
}

const char *audio_audfmt_to_string (audfmt_e fmt)
{
    switch (fmt) {
    case AUD_FMT_U8:
        return "U8";

    case AUD_FMT_U16:
        return "U16";

    case AUD_FMT_S8:
        return "S8";

    case AUD_FMT_S16:
        return "S16";
    }

    dolog ("Bogus audfmt %d returning S16\n", fmt);
    return "S16";
}

audfmt_e audio_string_to_audfmt (const char *s, audfmt_e defval, int *defaultp)
{
    if (!strcasecmp (s, "u8")) {
        *defaultp = 0;
        return AUD_FMT_U8;
    }
    else if (!strcasecmp (s, "u16")) {
        *defaultp = 0;
        return AUD_FMT_U16;
    }
    else if (!strcasecmp (s, "s8")) {
        *defaultp = 0;
        return AUD_FMT_S8;
    }
    else if (!strcasecmp (s, "s16")) {
        *defaultp = 0;
        return AUD_FMT_S16;
    }
    else {
        dolog ("Bogus audio format `%s' using %s\n",
               s, audio_audfmt_to_string (defval));
        *defaultp = 1;
        return defval;
    }
}

static audfmt_e audio_get_conf_fmt (const char *envname,
                                    audfmt_e defval,
                                    int *defaultp)
{
    const char *var = getenv (envname);
    if (!var) {
        *defaultp = 1;
        return defval;
    }
    return audio_string_to_audfmt (var, defval, defaultp);
}

static int audio_get_conf_int (const char *key, int defval, int *defaultp)
{
    int val;
    char *strval;

    strval = getenv (key);
    if (strval) {
        *defaultp = 0;
        val = atoi (strval);
        return val;
    }
    else {
        *defaultp = 1;
        return defval;
    }
}

static const char *audio_get_conf_str (const char *key,
                                       const char *defval,
                                       int *defaultp)
{
    const char *val = getenv (key);
    if (!val) {
        *defaultp = 1;
        return defval;
    }
    else {
        *defaultp = 0;
        return val;
    }
}

void AUD_vlog (const char *cap, const char *fmt, va_list ap)
{
    if (conf.log_to_monitor) {
        if (cap) {
            term_printf ("%s: ", cap);
        }

        term_vprintf (fmt, ap);
    }
    else {
        if (cap) {
            fprintf (stderr, "%s: ", cap);
        }

        vfprintf (stderr, fmt, ap);
    }
}

void AUD_log (const char *cap, const char *fmt, ...)
{
    va_list ap;

    va_start (ap, fmt);
    AUD_vlog (cap, fmt, ap);
    va_end (ap);
}

static void audio_print_options (const char *prefix,
                                 struct audio_option *opt)
{
    char *uprefix;

    if (!prefix) {
        dolog ("No prefix specified\n");
        return;
    }

    if (!opt) {
        dolog ("No options\n");
        return;
    }

    uprefix = audio_alloc_prefix (prefix);

    for (; opt->name; opt++) {
        const char *state = "default";
        printf ("  %s_%s: ", uprefix, opt->name);

        if (opt->overridenp && *opt->overridenp) {
            state = "current";
        }

        switch (opt->tag) {
        case AUD_OPT_BOOL:
            {
                int *intp = opt->valp;
                printf ("boolean, %s = %d\n", state, *intp ? 1 : 0);
            }
            break;

        case AUD_OPT_INT:
            {
                int *intp = opt->valp;
                printf ("integer, %s = %d\n", state, *intp);
            }
            break;

        case AUD_OPT_FMT:
            {
                audfmt_e *fmtp = opt->valp;
                printf (
                    "format, %s = %s, (one of: U8 S8 U16 S16)\n",
                    state,
                    audio_audfmt_to_string (*fmtp)
                    );
            }
            break;

        case AUD_OPT_STR:
            {
                const char **strp = opt->valp;
                printf ("string, %s = %s\n",
                        state,
                        *strp ? *strp : "(not set)");
            }
            break;

        default:
            printf ("???\n");
            dolog ("Bad value tag for option %s_%s %d\n",
                   uprefix, opt->name, opt->tag);
            break;
        }
        printf ("    %s\n", opt->descr);
    }

    qemu_free (uprefix);
}

static void audio_process_options (const char *prefix,
                                   struct audio_option *opt)
{
    char *optname;
    const char qemu_prefix[] = "QEMU_";
    size_t preflen;

    if (audio_bug (AUDIO_FUNC, !prefix)) {
        dolog ("prefix = NULL\n");
        return;
    }

    if (audio_bug (AUDIO_FUNC, !opt)) {
        dolog ("opt = NULL\n");
        return;
    }

    preflen = strlen (prefix);

    for (; opt->name; opt++) {
        size_t len, i;
        int def;

        if (!opt->valp) {
            dolog ("Option value pointer for `%s' is not set\n",
                   opt->name);
            continue;
        }

        len = strlen (opt->name);
        /* len of opt->name + len of prefix + size of qemu_prefix
         * (includes trailing zero) + zero + underscore (on behalf of
         * sizeof) */
        optname = qemu_malloc (len + preflen + sizeof (qemu_prefix) + 1);
        if (!optname) {
            dolog ("Could not allocate memory for option name `%s'\n",
                   opt->name);
            continue;
        }

        strcpy (optname, qemu_prefix);

        /* copy while upper-casing, including trailing zero */
        for (i = 0; i <= preflen; ++i) {
            optname[i + sizeof (qemu_prefix) - 1] = toupper (prefix[i]);
        }
        strcat (optname, "_");
        strcat (optname, opt->name);

        def = 1;
        switch (opt->tag) {
        case AUD_OPT_BOOL:
        case AUD_OPT_INT:
            {
                int *intp = opt->valp;
                *intp = audio_get_conf_int (optname, *intp, &def);
            }
            break;

        case AUD_OPT_FMT:
            {
                audfmt_e *fmtp = opt->valp;
                *fmtp = audio_get_conf_fmt (optname, *fmtp, &def);
            }
            break;

        case AUD_OPT_STR:
            {
                const char **strp = opt->valp;
                *strp = audio_get_conf_str (optname, *strp, &def);
            }
            break;

        default:
            dolog ("Bad value tag for option `%s' - %d\n",
                   optname, opt->tag);
            break;
        }

        if (!opt->overridenp) {
            opt->overridenp = &opt->overriden;
        }
        *opt->overridenp = !def;
        qemu_free (optname);
    }
}

static void audio_print_settings (audsettings_t *as)
{
    dolog ("frequency=%d nchannels=%d fmt=", as->freq, as->nchannels);

    switch (as->fmt) {
    case AUD_FMT_S8:
        AUD_log (NULL, "S8");
        break;
    case AUD_FMT_U8:
        AUD_log (NULL, "U8");
        break;
    case AUD_FMT_S16:
        AUD_log (NULL, "S16");
        break;
    case AUD_FMT_U16:
        AUD_log (NULL, "U16");
        break;
    default:
        AUD_log (NULL, "invalid(%d)", as->fmt);
        break;
    }
    AUD_log (NULL, "\n");
}

static int audio_validate_settigs (audsettings_t *as)
{
    int invalid;

    invalid = as->nchannels != 1 && as->nchannels != 2;

    switch (as->fmt) {
    case AUD_FMT_S8:
    case AUD_FMT_U8:
    case AUD_FMT_S16:
    case AUD_FMT_U16:
        break;
    default:
        invalid = 1;
        break;
    }

    invalid |= as->freq <= 0;

    if (invalid) {
        return -1;
    }
    return 0;
}

static int audio_pcm_info_eq (struct audio_pcm_info *info, audsettings_t *as)
{
    int bits = 8, sign = 0;

    switch (as->fmt) {
    case AUD_FMT_S8:
        sign = 1;
    case AUD_FMT_U8:
        break;

    case AUD_FMT_S16:
        sign = 1;
    case AUD_FMT_U16:
        bits = 16;
        break;
    }
    return info->freq == as->freq
        && info->nchannels == as->nchannels
        && info->sign == sign
        && info->bits == bits;
}

void audio_pcm_init_info (
    struct audio_pcm_info *info,
    audsettings_t *as,
    int swap_endian
    )
{
    int bits = 8, sign = 0;

    switch (as->fmt) {
    case AUD_FMT_S8:
        sign = 1;
    case AUD_FMT_U8:
        break;

    case AUD_FMT_S16:
        sign = 1;
    case AUD_FMT_U16:
        bits = 16;
        break;
    }

    info->freq = as->freq;
    info->bits = bits;
    info->sign = sign;
    info->nchannels = as->nchannels;
    info->shift = (as->nchannels == 2) + (bits == 16);
    info->align = (1 << info->shift) - 1;
    info->bytes_per_second = info->freq << info->shift;
    info->swap_endian = swap_endian;
}

void audio_pcm_info_clear_buf (struct audio_pcm_info *info, void *buf, int len)
{
    if (!len) {
        return;
    }

    if (info->sign) {
        memset (buf, len << info->shift, 0x00);
    }
    else {
        if (info->bits == 8) {
            memset (buf, len << info->shift, 0x80);
        }
        else {
            int i;
            uint16_t *p = buf;
            int shift = info->nchannels - 1;
            short s = INT16_MAX;

            if (info->swap_endian) {
                s = bswap16 (s);
            }

            for (i = 0; i < len << shift; i++) {
                p[i] = s;
            }
        }
    }
}

/*
 * Hard voice (capture)
 */
static int audio_pcm_hw_find_min_in (HWVoiceIn *hw)
{
    SWVoiceIn *sw;
    int m = hw->total_samples_captured;

    for (sw = hw->sw_head.lh_first; sw; sw = sw->entries.le_next) {
        if (sw->active) {
            m = audio_MIN (m, sw->total_hw_samples_acquired);
        }
    }
    return m;
}

int audio_pcm_hw_get_live_in (HWVoiceIn *hw)
{
    int live = hw->total_samples_captured - audio_pcm_hw_find_min_in (hw);
    if (audio_bug (AUDIO_FUNC, live < 0 || live > hw->samples)) {
        dolog ("live=%d hw->samples=%d\n", live, hw->samples);
        return 0;
    }
    return live;
}

/*
 * Soft voice (capture)
 */
static int audio_pcm_sw_get_rpos_in (SWVoiceIn *sw)
{
    HWVoiceIn *hw = sw->hw;
    int live = hw->total_samples_captured - sw->total_hw_samples_acquired;
    int rpos;

    if (audio_bug (AUDIO_FUNC, live < 0 || live > hw->samples)) {
        dolog ("live=%d hw->samples=%d\n", live, hw->samples);
        return 0;
    }

    rpos = hw->wpos - live;
    if (rpos >= 0) {
        return rpos;
    }
    else {
        return hw->samples + rpos;
    }
}

int audio_pcm_sw_read (SWVoiceIn *sw, void *buf, int size)
{
    HWVoiceIn *hw = sw->hw;
    int samples, live, ret = 0, swlim, isamp, osamp, rpos, total = 0;
    st_sample_t *src, *dst = sw->buf;

    rpos = audio_pcm_sw_get_rpos_in (sw) % hw->samples;

    live = hw->total_samples_captured - sw->total_hw_samples_acquired;
    if (audio_bug (AUDIO_FUNC, live < 0 || live > hw->samples)) {
        dolog ("live_in=%d hw->samples=%d\n", live, hw->samples);
        return 0;
    }

    samples = size >> sw->info.shift;
    if (!live) {
        return 0;
    }

    swlim = (live * sw->ratio) >> 32;
    swlim = audio_MIN (swlim, samples);

    while (swlim) {
        src = hw->conv_buf + rpos;
        isamp = hw->wpos - rpos;
        /* XXX: <= ? */
        if (isamp <= 0) {
            isamp = hw->samples - rpos;
        }

        if (!isamp) {
            break;
        }
        osamp = swlim;

        if (audio_bug (AUDIO_FUNC, osamp < 0)) {
            dolog ("osamp=%d\n", osamp);
            return 0;
        }

        st_rate_flow (sw->rate, src, dst, &isamp, &osamp);
        swlim -= osamp;
        rpos = (rpos + isamp) % hw->samples;
        dst += osamp;
        ret += osamp;
        total += isamp;
    }

    sw->clip (buf, sw->buf, ret);
    sw->total_hw_samples_acquired += total;
    return ret << sw->info.shift;
}

/*
 * Hard voice (playback)
 */
static int audio_pcm_hw_find_min_out (HWVoiceOut *hw, int *nb_livep)
{
    SWVoiceOut *sw;
    int m = INT_MAX;
    int nb_live = 0;

    for (sw = hw->sw_head.lh_first; sw; sw = sw->entries.le_next) {
        if (sw->active || !sw->empty) {
            m = audio_MIN (m, sw->total_hw_samples_mixed);
            nb_live += 1;
        }
    }

    *nb_livep = nb_live;
    return m;
}

int audio_pcm_hw_get_live_out2 (HWVoiceOut *hw, int *nb_live)
{
    int smin;

    smin = audio_pcm_hw_find_min_out (hw, nb_live);

    if (!*nb_live) {
        return 0;
    }
    else {
        int live = smin;

        if (audio_bug (AUDIO_FUNC, live < 0 || live > hw->samples)) {
            dolog ("live=%d hw->samples=%d\n", live, hw->samples);
            return 0;
        }
        return live;
    }
}

int audio_pcm_hw_get_live_out (HWVoiceOut *hw)
{
    int nb_live;
    int live;

    live = audio_pcm_hw_get_live_out2 (hw, &nb_live);
    if (audio_bug (AUDIO_FUNC, live < 0 || live > hw->samples)) {
        dolog ("live=%d hw->samples=%d\n", live, hw->samples);
        return 0;
    }
    return live;
}

/*
 * Soft voice (playback)
 */
int audio_pcm_sw_write (SWVoiceOut *sw, void *buf, int size)
{
    int hwsamples, samples, isamp, osamp, wpos, live, dead, left, swlim, blck;
    int ret = 0, pos = 0, total = 0;

    if (!sw) {
        return size;
    }

    hwsamples = sw->hw->samples;

    live = sw->total_hw_samples_mixed;
    if (audio_bug (AUDIO_FUNC, live < 0 || live > hwsamples)){
        dolog ("live=%d hw->samples=%d\n", live, hwsamples);
        return 0;
    }

    if (live == hwsamples) {
        return 0;
    }

    wpos = (sw->hw->rpos + live) % hwsamples;
    samples = size >> sw->info.shift;

    dead = hwsamples - live;
    swlim = ((int64_t) dead << 32) / sw->ratio;
    swlim = audio_MIN (swlim, samples);
    if (swlim) {
        sw->conv (sw->buf, buf, swlim, &sw->vol);
    }

    while (swlim) {
        dead = hwsamples - live;
        left = hwsamples - wpos;
        blck = audio_MIN (dead, left);
        if (!blck) {
            break;
        }
        isamp = swlim;
        osamp = blck;
        st_rate_flow_mix (
            sw->rate,
            sw->buf + pos,
            sw->hw->mix_buf + wpos,
            &isamp,
            &osamp
            );
        ret += isamp;
        swlim -= isamp;
        pos += isamp;
        live += osamp;
        wpos = (wpos + osamp) % hwsamples;
        total += osamp;
    }

    sw->total_hw_samples_mixed += total;
    sw->empty = sw->total_hw_samples_mixed == 0;

#ifdef DEBUG_OUT
    dolog (
        "%s: write size %d ret %d total sw %d\n",
        SW_NAME (sw),
        size >> sw->info.shift,
        ret,
        sw->total_hw_samples_mixed
        );
#endif

    return ret << sw->info.shift;
}

#ifdef DEBUG_AUDIO
static void audio_pcm_print_info (const char *cap, struct audio_pcm_info *info)
{
    dolog ("%s: bits %d, sign %d, freq %d, nchan %d\n",
           cap, info->bits, info->sign, info->freq, info->nchannels);
}
#endif

#define DAC
#include "audio_template.h"
#undef DAC
#include "audio_template.h"

int AUD_write (SWVoiceOut *sw, void *buf, int size)
{
    int bytes;

    if (!sw) {
        /* XXX: Consider options */
        return size;
    }

    if (!sw->hw->enabled) {
        dolog ("Writing to disabled voice %s\n", SW_NAME (sw));
        return 0;
    }

    bytes = sw->hw->pcm_ops->write (sw, buf, size);
    return bytes;
}

int AUD_read (SWVoiceIn *sw, void *buf, int size)
{
    int bytes;

    if (!sw) {
        /* XXX: Consider options */
        return size;
    }

    if (!sw->hw->enabled) {
        dolog ("Reading from disabled voice %s\n", SW_NAME (sw));
        return 0;
    }

    bytes = sw->hw->pcm_ops->read (sw, buf, size);
    return bytes;
}

int AUD_get_buffer_size_out (SWVoiceOut *sw)
{
    return sw->hw->samples << sw->hw->info.shift;
}

void AUD_set_active_out (SWVoiceOut *sw, int on)
{
    HWVoiceOut *hw;

    if (!sw) {
        return;
    }

    hw = sw->hw;
    if (sw->active != on) {
        SWVoiceOut *temp_sw;

        if (on) {
            int total;

            hw->pending_disable = 0;
            if (!hw->enabled) {
                hw->enabled = 1;
                hw->pcm_ops->ctl_out (hw, VOICE_ENABLE);
            }

            if (sw->empty) {
                total = 0;
            }
        }
        else {
            if (hw->enabled) {
                int nb_active = 0;

                for (temp_sw = hw->sw_head.lh_first; temp_sw;
                     temp_sw = temp_sw->entries.le_next) {
                    nb_active += temp_sw->active != 0;
                }

                hw->pending_disable = nb_active == 1;
            }
        }
        sw->active = on;
    }
}

void AUD_set_active_in (SWVoiceIn *sw, int on)
{
    HWVoiceIn *hw;

    if (!sw) {
        return;
    }

    hw = sw->hw;
    if (sw->active != on) {
        SWVoiceIn *temp_sw;

        if (on) {
            if (!hw->enabled) {
                hw->enabled = 1;
                hw->pcm_ops->ctl_in (hw, VOICE_ENABLE);
            }
            sw->total_hw_samples_acquired = hw->total_samples_captured;
        }
        else {
            if (hw->enabled) {
                int nb_active = 0;

                for (temp_sw = hw->sw_head.lh_first; temp_sw;
                     temp_sw = temp_sw->entries.le_next) {
                    nb_active += temp_sw->active != 0;
                }

                if (nb_active == 1) {
                    hw->enabled = 0;
                    hw->pcm_ops->ctl_in (hw, VOICE_DISABLE);
                }
            }
        }
        sw->active = on;
    }
}

static int audio_get_avail (SWVoiceIn *sw)
{
    int live;

    if (!sw) {
        return 0;
    }

    live = sw->hw->total_samples_captured - sw->total_hw_samples_acquired;
    if (audio_bug (AUDIO_FUNC, live < 0 || live > sw->hw->samples)) {
        dolog ("live=%d sw->hw->samples=%d\n", live, sw->hw->samples);
        return 0;
    }

    ldebug (
        "%s: get_avail live %d ret %lld\n",
        SW_NAME (sw),
        live, (((int64_t) live << 32) / sw->ratio) << sw->info.shift
        );

    return (((int64_t) live << 32) / sw->ratio) << sw->info.shift;
}

static int audio_get_free (SWVoiceOut *sw)
{
    int live, dead;

    if (!sw) {
        return 0;
    }

    live = sw->total_hw_samples_mixed;

    if (audio_bug (AUDIO_FUNC, live < 0 || live > sw->hw->samples)) {
        dolog ("live=%d sw->hw->samples=%d\n", live, sw->hw->samples);
        return 0;
    }

    dead = sw->hw->samples - live;

#ifdef DEBUG_OUT
    dolog ("%s: get_free live %d dead %d ret %lld\n",
           SW_NAME (sw),
           live, dead, (((int64_t) dead << 32) / sw->ratio) << sw->info.shift);
#endif

    return (((int64_t) dead << 32) / sw->ratio) << sw->info.shift;
}

static void audio_run_out (AudioState *s)
{
    HWVoiceOut *hw = NULL;
    SWVoiceOut *sw;

    while ((hw = audio_pcm_hw_find_any_enabled_out (s, hw))) {
        int played;
        int live, free, nb_live, cleanup_required;

        live = audio_pcm_hw_get_live_out2 (hw, &nb_live);
        if (!nb_live) {
            live = 0;
        }

        if (audio_bug (AUDIO_FUNC, live < 0 || live > hw->samples)) {
            dolog ("live=%d hw->samples=%d\n", live, hw->samples);
            continue;
        }

        if (hw->pending_disable && !nb_live) {
#ifdef DEBUG_OUT
            dolog ("Disabling voice\n");
#endif
            hw->enabled = 0;
            hw->pending_disable = 0;
            hw->pcm_ops->ctl_out (hw, VOICE_DISABLE);
            continue;
        }

        if (!live) {
            for (sw = hw->sw_head.lh_first; sw; sw = sw->entries.le_next) {
                if (sw->active) {
                    free = audio_get_free (sw);
                    if (free > 0) {
                        sw->callback.fn (sw->callback.opaque, free);
                    }
                }
            }
            continue;
        }

        played = hw->pcm_ops->run_out (hw);
        if (audio_bug (AUDIO_FUNC, hw->rpos >= hw->samples)) {
            dolog ("hw->rpos=%d hw->samples=%d played=%d\n",
                   hw->rpos, hw->samples, played);
            hw->rpos = 0;
        }

#ifdef DEBUG_OUT
        dolog ("played=%d\n", played);
#endif

        if (played) {
            hw->ts_helper += played;
        }

        cleanup_required = 0;
        for (sw = hw->sw_head.lh_first; sw; sw = sw->entries.le_next) {
            if (!sw->active && sw->empty) {
                continue;
            }

            if (audio_bug (AUDIO_FUNC, played > sw->total_hw_samples_mixed)) {
                dolog ("played=%d sw->total_hw_samples_mixed=%d\n",
                       played, sw->total_hw_samples_mixed);
                played = sw->total_hw_samples_mixed;
            }

            sw->total_hw_samples_mixed -= played;

            if (!sw->total_hw_samples_mixed) {
                sw->empty = 1;
                cleanup_required |= !sw->active && !sw->callback.fn;
            }

            if (sw->active) {
                free = audio_get_free (sw);
                if (free > 0) {
                    sw->callback.fn (sw->callback.opaque, free);
                }
            }
        }

        if (cleanup_required) {
        restart:
            for (sw = hw->sw_head.lh_first; sw; sw = sw->entries.le_next) {
                if (!sw->active && !sw->callback.fn) {
#ifdef DEBUG_PLIVE
                    dolog ("Finishing with old voice\n");
#endif
                    audio_close_out (s, sw);
                    goto restart; /* play it safe */
                }
            }
        }
    }
}

static void audio_run_in (AudioState *s)
{
    HWVoiceIn *hw = NULL;

    while ((hw = audio_pcm_hw_find_any_enabled_in (s, hw))) {
        SWVoiceIn *sw;
        int captured, min;

        captured = hw->pcm_ops->run_in (hw);

        min = audio_pcm_hw_find_min_in (hw);
        hw->total_samples_captured += captured - min;
        hw->ts_helper += captured;

        for (sw = hw->sw_head.lh_first; sw; sw = sw->entries.le_next) {
            sw->total_hw_samples_acquired -= min;

            if (sw->active) {
                int avail;

                avail = audio_get_avail (sw);
                if (avail > 0) {
                    sw->callback.fn (sw->callback.opaque, avail);
                }
            }
        }
    }
}

static void audio_timer (void *opaque)
{
    AudioState *s = opaque;

    audio_run_out (s);
    audio_run_in (s);

    qemu_mod_timer (s->ts, qemu_get_clock (vm_clock) + conf.period.ticks);
}

static struct audio_option audio_options[] = {
    /* DAC */
    {"DAC_FIXED_SETTINGS", AUD_OPT_BOOL, &conf.fixed_out.enabled,
     "Use fixed settings for host DAC", NULL, 0},

    {"DAC_FIXED_FREQ", AUD_OPT_INT, &conf.fixed_out.settings.freq,
     "Frequency for fixed host DAC", NULL, 0},

    {"DAC_FIXED_FMT", AUD_OPT_FMT, &conf.fixed_out.settings.fmt,
     "Format for fixed host DAC", NULL, 0},

    {"DAC_FIXED_CHANNELS", AUD_OPT_INT, &conf.fixed_out.settings.nchannels,
     "Number of channels for fixed DAC (1 - mono, 2 - stereo)", NULL, 0},

    {"DAC_VOICES", AUD_OPT_INT, &conf.fixed_out.nb_voices,
     "Number of voices for DAC", NULL, 0},

    /* ADC */
    {"ADC_FIXED_SETTINGS", AUD_OPT_BOOL, &conf.fixed_in.enabled,
     "Use fixed settings for host ADC", NULL, 0},

    {"ADC_FIXED_FREQ", AUD_OPT_INT, &conf.fixed_in.settings.freq,
     "Frequency for fixed host ADC", NULL, 0},

    {"ADC_FIXED_FMT", AUD_OPT_FMT, &conf.fixed_in.settings.fmt,
     "Format for fixed host ADC", NULL, 0},

    {"ADC_FIXED_CHANNELS", AUD_OPT_INT, &conf.fixed_in.settings.nchannels,
     "Number of channels for fixed ADC (1 - mono, 2 - stereo)", NULL, 0},

    {"ADC_VOICES", AUD_OPT_INT, &conf.fixed_in.nb_voices,
     "Number of voices for ADC", NULL, 0},

    /* Misc */
    {"TIMER_PERIOD", AUD_OPT_INT, &conf.period.hz,
     "Timer period in HZ (0 - use lowest possible)", NULL, 0},

    {"PLIVE", AUD_OPT_BOOL, &conf.plive,
     "(undocumented)", NULL, 0},

    {"LOG_TO_MONITOR", AUD_OPT_BOOL, &conf.log_to_monitor,
     "print logging messages to montior instead of stderr", NULL, 0},

    {NULL, 0, NULL, NULL, NULL, 0}
};

static void audio_pp_nb_voices (const char *typ, int nb)
{
    switch (nb) {
    case 0:
        printf ("Does not support %s\n", typ);
        break;
    case 1:
        printf ("One %s voice\n", typ);
        break;
    case INT_MAX:
        printf ("Theoretically supports many %s voices\n", typ);
        break;
    default:
        printf ("Theoretically supports upto %d %s voices\n", nb, typ);
        break;
    }

}

void AUD_help (void)
{
    size_t i;

    audio_process_options ("AUDIO", audio_options);
    for (i = 0; i < sizeof (drvtab) / sizeof (drvtab[0]); i++) {
        struct audio_driver *d = drvtab[i];
        if (d->options) {
            audio_process_options (d->name, d->options);
        }
    }

    printf ("Audio options:\n");
    audio_print_options ("AUDIO", audio_options);
    printf ("\n");

    printf ("Available drivers:\n");

    for (i = 0; i < sizeof (drvtab) / sizeof (drvtab[0]); i++) {
        struct audio_driver *d = drvtab[i];

        printf ("Name: %s\n", d->name);
        printf ("Description: %s\n", d->descr);

        audio_pp_nb_voices ("playback", d->max_voices_out);
        audio_pp_nb_voices ("capture", d->max_voices_in);

        if (d->options) {
            printf ("Options:\n");
            audio_print_options (d->name, d->options);
        }
        else {
            printf ("No options\n");
        }
        printf ("\n");
    }

    printf (
        "Options are settable through environment variables.\n"
        "Example:\n"
#ifdef _WIN32
        "  set QEMU_AUDIO_DRV=wav\n"
        "  set QEMU_WAV_PATH=c:\\tune.wav\n"
#else
        "  export QEMU_AUDIO_DRV=wav\n"
        "  export QEMU_WAV_PATH=$HOME/tune.wav\n"
        "(for csh replace export with setenv in the above)\n"
#endif
        "  qemu ...\n\n"
        );
}

static int audio_driver_init (AudioState *s, struct audio_driver *drv)
{
    if (drv->options) {
        audio_process_options (drv->name, drv->options);
    }
    s->drv_opaque = drv->init ();

    if (s->drv_opaque) {
        audio_init_nb_voices_out (s, drv);
        audio_init_nb_voices_in (s, drv);
        s->drv = drv;
        return 0;
    }
    else {
        dolog ("Could not init `%s' audio driver\n", drv->name);
        return -1;
    }
}

static void audio_vm_change_state_handler (void *opaque, int running)
{
    AudioState *s = opaque;
    HWVoiceOut *hwo = NULL;
    HWVoiceIn *hwi = NULL;
    int op = running ? VOICE_ENABLE : VOICE_DISABLE;

    while ((hwo = audio_pcm_hw_find_any_enabled_out (s, hwo))) {
        hwo->pcm_ops->ctl_out (hwo, op);
    }

    while ((hwi = audio_pcm_hw_find_any_enabled_in (s, hwi))) {
        hwi->pcm_ops->ctl_in (hwi, op);
    }
}

static void audio_atexit (void)
{
    AudioState *s = &glob_audio_state;
    HWVoiceOut *hwo = NULL;
    HWVoiceIn *hwi = NULL;

    while ((hwo = audio_pcm_hw_find_any_enabled_out (s, hwo))) {
        hwo->pcm_ops->ctl_out (hwo, VOICE_DISABLE);
        hwo->pcm_ops->fini_out (hwo);
    }

    while ((hwi = audio_pcm_hw_find_any_enabled_in (s, hwi))) {
        hwi->pcm_ops->ctl_in (hwi, VOICE_DISABLE);
        hwi->pcm_ops->fini_in (hwi);
    }

    if (s->drv) {
        s->drv->fini (s->drv_opaque);
    }
}

static void audio_save (QEMUFile *f, void *opaque)
{
    (void) f;
    (void) opaque;
}

static int audio_load (QEMUFile *f, void *opaque, int version_id)
{
    (void) f;
    (void) opaque;

    if (version_id != 1) {
        return -EINVAL;
    }

    return 0;
}

void AUD_register_card (AudioState *s, const char *name, QEMUSoundCard *card)
{
    card->audio = s;
    card->name = qemu_strdup (name);
    memset (&card->entries, 0, sizeof (card->entries));
    LIST_INSERT_HEAD (&s->card_head, card, entries);
}

void AUD_remove_card (QEMUSoundCard *card)
{
    LIST_REMOVE (card, entries);
    card->audio = NULL;
    qemu_free (card->name);
}

AudioState *AUD_init (void)
{
    size_t i;
    int done = 0;
    const char *drvname;
    AudioState *s = &glob_audio_state;

    LIST_INIT (&s->hw_head_out);
    LIST_INIT (&s->hw_head_in);
    atexit (audio_atexit);

    s->ts = qemu_new_timer (vm_clock, audio_timer, s);
    if (!s->ts) {
        dolog ("Could not create audio timer\n");
        return NULL;
    }

    audio_process_options ("AUDIO", audio_options);

    s->nb_hw_voices_out = conf.fixed_out.nb_voices;
    s->nb_hw_voices_in = conf.fixed_in.nb_voices;

    if (s->nb_hw_voices_out <= 0) {
        dolog ("Bogus number of playback voices %d, setting to 1\n",
               s->nb_hw_voices_out);
        s->nb_hw_voices_out = 1;
    }

    if (s->nb_hw_voices_in <= 0) {
        dolog ("Bogus number of capture voices %d, setting to 0\n",
               s->nb_hw_voices_in);
        s->nb_hw_voices_in = 0;
    }

    {
        int def;
        drvname = audio_get_conf_str ("QEMU_AUDIO_DRV", NULL, &def);
    }

    if (drvname) {
        int found = 0;

        for (i = 0; i < sizeof (drvtab) / sizeof (drvtab[0]); i++) {
            if (!strcmp (drvname, drvtab[i]->name)) {
                done = !audio_driver_init (s, drvtab[i]);
                found = 1;
                break;
            }
        }

        if (!found) {
            dolog ("Unknown audio driver `%s'\n", drvname);
            dolog ("Run with -audio-help to list available drivers\n");
        }
    }

    if (!done) {
        for (i = 0; !done && i < sizeof (drvtab) / sizeof (drvtab[0]); i++) {
            if (drvtab[i]->can_be_default) {
                done = !audio_driver_init (s, drvtab[i]);
            }
        }
    }

    if (!done) {
        done = !audio_driver_init (s, &no_audio_driver);
        if (!done) {
            dolog ("Could not initialize audio subsystem\n");
        }
        else {
            dolog ("warning: Using timer based audio emulation\n");
        }
    }

    if (done) {
        VMChangeStateEntry *e;

        if (conf.period.hz <= 0) {
            if (conf.period.hz < 0) {
                dolog ("warning: Timer period is negative - %d "
                       "treating as zero\n",
                       conf.period.hz);
            }
            conf.period.ticks = 1;
        }
        else {
            conf.period.ticks = ticks_per_sec / conf.period.hz;
        }

        e = qemu_add_vm_change_state_handler (audio_vm_change_state_handler, s);
        if (!e) {
            dolog ("warning: Could not register change state handler\n"
                   "(Audio can continue looping even after stopping the VM)\n");
        }
    }
    else {
        qemu_del_timer (s->ts);
        return NULL;
    }

    LIST_INIT (&s->card_head);
    register_savevm ("audio", 0, 1, audio_save, audio_load, s);
    qemu_mod_timer (s->ts, qemu_get_clock (vm_clock) + conf.period.ticks);
    return s;
}

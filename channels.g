#ifndef CHANNELS_H
#define CHANNELS_H

/* total number of channels including canonical "local" and "remote" channels */
#define CHANNELS NUMCHANNELS

/* supplemental channels are all channels less the canonical "local" and "remote" channels */
#define SUPPL_CHANNELS (CHANNELS - 2)

/* Not longer than 80 bytes, must also change qmail-upq.sh */
#define QDIR_BASENAME "suppl"

/* start supplemental channel fd numbers here */
#define CHANNEL_FD_OFFSET 10


#endif


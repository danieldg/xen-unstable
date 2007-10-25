#ifndef _XENFB_H_
#define _XENFB_H_

#include "vl.h"
#include <stdbool.h>
#include <sys/types.h>

struct xenfb
{
	void *pixels;

	int row_stride;
	int depth;
	int width;
	int height;
	int abs_pointer_wanted;
	int button_state;

	void *user_data;

	void (*update)(struct xenfb *xenfb, int x, int y, int width, int height);
};

struct xenfb *xenfb_new(void);
void xenfb_delete(struct xenfb *xenfb);
void xenfb_teardown(struct xenfb *xenfb);

int xenfb_attach_dom(struct xenfb *xenfb, int domid, DisplayState *ds);

#endif

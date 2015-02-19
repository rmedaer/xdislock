#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <security/pam_appl.h>

#include <X11/X.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

#include <pthread.h>

#include "pixmap.h"

#define MAX_PROMPT_LENGTH 800
#define PAM_SERVICE_NAME  "xdislock"

extern char *strdup(const char *s);

int pam_prompt_flag = 0;
char prompt[MAX_PROMPT_LENGTH];
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  cond = PTHREAD_COND_INITIALIZER;
Display *display;
Cursor cursor;
XColor color;


/**
 * Recolorize cursor with specified color (r,g,b){0-255}
 */
void recolor_cursor(
    Cursor *cursor,
    int r, int g, int b)
{
    int rc;

    XLockDisplay(display);

    color.red   = r * 65535 / 255;
    color.green = g * 65535 / 255;
    color.blue  = b * 65535 / 255;

    rc = XRecolorCursor(
        display,
        *cursor,
        &color,
        &color);
    if (! rc) {
        fprintf(stderr, "failed to recolor cursor\n");
        return;
    }

    XFlush(display);

    XUnlockDisplay(display);
}

/**
 * PAM prompt callback. Replace default input from stdin.
 */
static int prompt_callback(
    int num_msg,
    const struct pam_message **msg,
    struct pam_response **resp,
    void *appdata_ptr)
{
    int i;
    struct pam_response *r;
    r = calloc(num_msg, sizeof(struct pam_response));
    if (r == NULL) {
        return PAM_BUF_ERR;
    }

    for (i = 0; i < num_msg; i++) {
        r[i].resp_retcode = 0;
        r[i].resp = NULL;

        switch (msg[i]->msg_style) {
            case PAM_ERROR_MSG:
            case PAM_TEXT_INFO:
            case PAM_PROMPT_ECHO_ON:
                break; // No matter
            case PAM_PROMPT_ECHO_OFF:
                // Lock and acquire mutex
                pthread_mutex_lock(&lock);

                // Enable prompt with flag
                pam_prompt_flag = 1;
                recolor_cursor(&cursor, 0, 0, 255);

                // Wait prompt validation signal
                pthread_cond_wait(&cond, &lock);
                recolor_cursor(&cursor, 255, 0, 0);

                // Disable prompt with flag
                pam_prompt_flag = 0;    // TODO protect this

                // Copy string
                r[i].resp = strdup(prompt);

                // Unlock mutex
                pthread_mutex_unlock(&lock);

                break;
        }
    }

    *resp = r;
    return PAM_SUCCESS;
}

static struct pam_conv conv = {
    prompt_callback,
    NULL
};

/**
 * Grab each events and complete prompt string.
 */
void *grab_events()
{
    XEvent event;
    unsigned int index = 0;

    for (;;) {
        XNextEvent(display, &event);

        if (event.type == KeyPress) {
            if (! pam_prompt_flag) {
                continue;
            }

            KeySym key;
            char buffer;
            int length;
            
            length = XLookupString(&event.xkey, &buffer, 1, &key, NULL);

            switch (key) {
                case XK_Escape:
                case XK_Clear:
                    index = 0;
                    break;

                case XK_Delete:
                case XK_BackSpace:
                    if (index > 0) {
                        index--;
                    }
                    break;

                case XK_Linefeed:
                case XK_Return:
                    prompt[index] = '\0';
                    index = 0;
                    pthread_cond_signal(&cond);
                    break;

                default:
                    if (length != 1) {
                        break;
                    }

                    if (index < (sizeof(prompt) - 1)) {
                        prompt[index] = buffer;
                        index++;
                    }
            }
        }
    }
}

int main(int argc, char *argv[])
{
    int rc;
    pthread_t x_thread, pam_thread;
    Pixmap pix_source, pix_mask;
    int authenticated = 0;
    pam_handle_t *pamh = NULL;

    // Enable multithreading
    XInitThreads();

    // Open display
    if ((display = XOpenDisplay(0)) == NULL) {
        fprintf(stderr, "cannot open display\n");
        exit(42);
    }

    rc = XAllocColor(
        display,
        DefaultColormap(display, DefaultScreen(display)),
        &color);
    if (! rc) {
        fprintf(stderr, "failed to alloc color\n");
        return;
    }

    // Get pixmap from data
    pix_source = XCreateBitmapFromData(
        display,
        DefaultRootWindow(display),
        pixmap_source_bits,
        PIXMAP_WIDTH,
        PIXMAP_HEIGHT);
    pix_mask = XCreateBitmapFromData(
        display,
        DefaultRootWindow(display),
        pixmap_mask_bits,
        PIXMAP_WIDTH,
        PIXMAP_HEIGHT);

    // Create cursor from pixmap
    cursor = XCreatePixmapCursor(
        display,
        pix_source,
        pix_mask,
        &color,
        &color,
        0,
        0);

    recolor_cursor(&cursor, 255, 255, 255);

    // Grab pointer
    rc = XGrabPointer(
        display,
        DefaultRootWindow(display),
        True,
        ButtonPressMask
            | ButtonReleaseMask
            | PointerMotionMask
            | FocusChangeMask
            | EnterWindowMask
            | LeaveWindowMask,
        GrabModeAsync,
        GrabModeAsync,
        None,
        cursor,
        CurrentTime);
    if (rc != GrabSuccess) {
        fprintf(stderr, "failed to grab pointer\n");
        exit(42);
    }

    // Grab keyboard
    rc = XGrabKeyboard(
        display,
        DefaultRootWindow(display),
        True,
        GrabModeAsync,
        GrabModeAsync,
        CurrentTime);
    if (rc != GrabSuccess) {
        fprintf(stderr, "failed to grab keyboard\n");
        exit(42);
    }

    // Start PAM
    rc = pam_start(PAM_SERVICE_NAME, getlogin(), &conv, &pamh);
    if (rc != PAM_SUCCESS) {
        fprintf(stderr, "failed to start pam");
        exit(42);
    }

    // Thread to grab events
    pthread_create(&x_thread, NULL, &grab_events, NULL);

    while (! authenticated) {
        printf("PAM retry\n");
        recolor_cursor(&cursor, 255, 255, 255);

        if (pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK) == PAM_SUCCESS
                && pam_acct_mgmt(pamh, 0) == PAM_SUCCESS) {
            authenticated = 1;
        }
    }
    
    rc = pam_end(pamh, rc);
    if (rc != PAM_SUCCESS) {
        fprintf(stderr, "failed to release authenticator\n");
        exit(42);
    }

}

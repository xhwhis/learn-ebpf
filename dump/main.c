#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <threads.h>

// Data structures.

#define MAX_MSG_SIZE 8000

enum TrafficDirectionT
{
    Ingress,
    Egress,
};

struct ConnIdT
{
    uint32_t pid;
    int32_t fd;
    uint64_t tsid;
};

struct AttrT
{
    uint64_t timestamp_ns;
    struct ConnIdT conn_id;
    enum TrafficDirectionT direction;
    uint32_t msg_size;
    uint64_t pos;
};

struct SocketDataEventT
{
    struct AttrT attr;
    char msg[MAX_MSG_SIZE];
};

struct FfiWakerVTable
{
    struct FfiWaker const *(*clone)(struct FfiWaker const *);
    void (*wake)(struct FfiWaker *);
    void (*wake_by_ref)(struct FfiWaker const *);
    void (*drop)(struct FfiWaker *);
};

struct FfiWaker
{
    struct FfiWakerVTable const *vtable;

    // Store some extra trailing data to wake up the executor loop.
    mtx_t *mutex;
    cnd_t *condvar;
    int *awake;
};

struct FfiContext
{
    struct FfiWaker const *waker_ref;
};

struct Poll
{
    uint8_t is_pending;
    union
    {
        struct SocketDataEventT value;
    };
};

struct FfiFuture
{
    void *fut;
    struct Poll (*poll)(void *fut, struct FfiContext *context);
    void (*drop)(void *fut);
};

// Waker virtual functions.

struct FfiWaker const *waker_clone(struct FfiWaker const *w)
{
    struct FfiWaker *p = malloc(sizeof(struct FfiWaker));
    assert(p);
    *p = *w;
    return p;
}

void waker_wake_by_ref(struct FfiWaker const *w)
{
    puts("Wake");
    mtx_lock(w->mutex);
    *w->awake = 1;
    cnd_signal(w->condvar);
    mtx_unlock(w->mutex);
}

void waker_drop(struct FfiWaker *w)
{
    free(w);
}

void waker_wake(struct FfiWaker *w)
{
    waker_wake_by_ref(w);
    waker_drop(w);
}

struct FfiWakerVTable waker_vtable = {
    .clone = &waker_clone,
    .wake = &waker_wake,
    .wake_by_ref = &waker_wake_by_ref,
    .drop = &waker_drop,
};

// Executor.

typedef void (*start_dump_fn_t)();
typedef void (*stop_dump_fn_t)();
typedef struct FfiFuture (*get_data_fn_t)();

void execute(get_data_fn_t fn)
{
    // Waker may outlive the executor itself, so data referenced by waker need to be reference-counted.
    // Here we simply use global one since the executor is run only once.
    static mtx_t mutex;
    static cnd_t condvar;
    static int awake = 0;
    mtx_init(&mutex, mtx_plain);
    cnd_init(&condvar);

    struct FfiWaker waker = {
        .vtable = &waker_vtable,
        .mutex = &mutex,
        .condvar = &condvar,
        .awake = &awake,
    };
    struct FfiContext ctx = {.waker_ref = &waker};

    puts("Calling future");
    struct FfiFuture fut = fn();

    struct Poll ret;
    while (1)
    {
        puts("Polling future");
        ret = (fut.poll)(fut.fut, &ctx);
        printf("-> is_pending: %d\n", ret.is_pending);
        if (!ret.is_pending)
            break;

        // When `poll` returns `Pending`, it automatically hook the waker to some reactor, which will
        // be called `wake` or `wake_by_ref` if the future is ready to be `poll`ed again.
        // So we wait on the condvar until someone wake us again.
        mtx_lock(&mutex);
        while (!awake)
            cnd_wait(&condvar, &mutex);
        awake = 0;
        mtx_unlock(&mutex);
    }
    // Drop the future when finished or canceled.
    (fut.drop)(fut.fut);

    printf("payload: %ld\n", ret.value.attr.timestamp_ns);
}

int main(int argc, char const **argv)
{
    assert(argc == 2);
    char const *lib_path = argv[1];

    void *dl = dlopen(lib_path, RTLD_LAZY);
    if (!dl)
    {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        exit(1);
    }
    dlerror(); // Clear errno.

    start_dump_fn_t start_dump_fn = dlsym(dl, "start_dump");
    char *dlerr;
    if ((dlerr = dlerror()) != 0)
    {
        fprintf(stderr, "dlsym failed: %s\n", dlerr);
        dlclose(dl);
        exit(1);
    }

    stop_dump_fn_t stop_dump_fn = dlsym(dl, "stop_dump");
    if ((dlerr = dlerror()) != 0)
    {
        fprintf(stderr, "dlsym failed: %s\n", dlerr);
        dlclose(dl);
        exit(1);
    }

    get_data_fn_t get_data_fn = dlsym(dl, "get_data");
    if ((dlerr = dlerror()) != 0)
    {
        fprintf(stderr, "dlsym failed: %s\n", dlerr);
        dlclose(dl);
        exit(1);
    }

    start_dump_fn();
    execute(get_data_fn);
    stop_dump_fn();

    dlclose(dl);
    return 0;
}

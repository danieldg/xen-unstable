#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__

#include <xen/config.h>
#include <asm/system.h>

#define spin_lock_irqsave(lock, flags) \
    do { local_irq_save(flags); spin_lock(lock); } while ( 0 )
#define spin_lock_irq(lock) \
    do { local_irq_disable(); spin_lock(lock); } while ( 0 )

#define read_lock_irqsave(lock, flags) \
    do { local_irq_save(flags); read_lock(lock); } while ( 0 )
#define read_lock_irq(lock) \
    do { local_irq_disable(); read_lock(lock); } while ( 0 )

#define write_lock_irqsave(lock, flags) \
    do { local_irq_save(flags); write_lock(lock); } while ( 0 )
#define write_lock_irq(lock) \
    do { local_irq_disable(); write_lock(lock); } while ( 0 )

#define spin_unlock_irqrestore(lock, flags) \
    do { spin_unlock(lock); local_irq_restore(flags); } while ( 0 )
#define spin_unlock_irq(lock) \
    do { spin_unlock(lock); local_irq_enable(); } while ( 0 )

#define read_unlock_irqrestore(lock, flags) \
    do { read_unlock(lock); local_irq_restore(flags); } while ( 0 )
#define read_unlock_irq(lock) \
    do { read_unlock(lock); local_irq_enable(); } while ( 0 )

#define write_unlock_irqrestore(lock, flags) \
    do { write_unlock(lock); local_irq_restore(flags); } while ( 0 )
#define write_unlock_irq(lock) \
    do { write_unlock(lock); local_irq_enable(); } while ( 0 )

#ifdef CONFIG_SMP

#include <asm/spinlock.h>

#else

#if (__GNUC__ > 2)
typedef struct { } spinlock_t;
#define SPIN_LOCK_UNLOCKED (spinlock_t) { }
#else
typedef struct { int gcc_is_buggy; } spinlock_t;
#define SPIN_LOCK_UNLOCKED (spinlock_t) { 0 }
#endif

#define spin_lock_init(lock)    do { } while(0)
#define spin_lock(lock)         (void)(lock) /* Not "unused variable". */
#define spin_is_locked(lock)    (0)
#define spin_trylock(lock)      ({1; })
#define spin_unlock_wait(lock)  do { } while(0)
#define spin_unlock(lock)       do { } while(0)

#if (__GNUC__ > 2)
typedef struct { } rwlock_t;
#define RW_LOCK_UNLOCKED (rwlock_t) { }
#else
typedef struct { int gcc_is_buggy; } rwlock_t;
#define RW_LOCK_UNLOCKED (rwlock_t) { 0 }
#endif

#define rwlock_init(lock)       do { } while(0)
#define read_lock(lock)         (void)(lock) /* Not "unused variable". */
#define read_unlock(lock)       do { } while(0)
#define write_lock(lock)        (void)(lock) /* Not "unused variable". */
#define write_unlock(lock)      do { } while(0)

#endif

#endif /* __SPINLOCK_H__ */

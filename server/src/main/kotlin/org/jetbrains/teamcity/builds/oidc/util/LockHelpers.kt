package org.jetbrains.teamcity.builds.oidc.util

import com.intellij.openapi.diagnostic.Logger
import jetbrains.buildServer.log.Loggers
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantReadWriteLock

val LOCK_TIMEOUT_LOG = Logger.getInstance(Loggers.SERVER_CATEGORY + ".OIDCLockTimeout")

inline fun <T> Lock.withTryLock(timeoutSeconds: Long, action: () -> T): T {
    if (!tryLock(timeoutSeconds, TimeUnit.SECONDS)) {
        val e = TimeoutException("Failed to acquire lock within $timeoutSeconds seconds")
        LOCK_TIMEOUT_LOG.error(e)
        throw e
    }
    try { return action() } finally { unlock() }
}

inline fun <T> ReentrantReadWriteLock.tryRead(timeoutSeconds: Long, action: () -> T): T =
    readLock().withTryLock(timeoutSeconds, action)

inline fun <T> ReentrantReadWriteLock.tryWrite(timeoutSeconds: Long, action: () -> T): T =
    writeLock().withTryLock(timeoutSeconds, action)

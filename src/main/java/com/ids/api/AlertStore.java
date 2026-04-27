package com.ids.api;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * DB-backed alert store.
 *
 * Every alert is persisted to MySQL via AlertRepository so data survives
 * restarts.  The most recent 100 alerts are also held in an in-memory
 * cache so WebSocket broadcasts and the dashboard's "recent" view remain
 * instantaneous without hitting the DB on every packet.
 */
@Component
public class AlertStore {

    private static final int CACHE_SIZE = 100;

    private final AlertRepository repository;

    /** Hot cache — newest first, max CACHE_SIZE entries. */
    private final CopyOnWriteArrayList<AlertDto> cache = new CopyOnWriteArrayList<>();

    public AlertStore(AlertRepository repository) {
        this.repository = repository;
        // Pre-warm cache from DB on startup (last CACHE_SIZE alerts)
        List<AlertEntity> recent = repository.findAll(
                org.springframework.data.domain.PageRequest.of(
                        0, CACHE_SIZE,
                        org.springframework.data.domain.Sort.by("timestamp").descending()
                )
        ).getContent();
        recent.forEach(e -> cache.add(e.toDto()));
    }

    /**
     * Persist a new alert to MySQL and push it to the front of the cache.
     */
    public void add(AlertDto alert) {
        // 1. Persist to DB
        repository.save(AlertEntity.fromDto(alert));

        // 2. Update in-memory cache (newest first)
        cache.add(0, alert);
        if (cache.size() > CACHE_SIZE) {
            cache.remove(cache.size() - 1);
        }
    }

    /**
     * Returns cached alerts (newest first, up to CACHE_SIZE).
     * For full history use the paginated DB query in AlertController.
     */
    public List<AlertDto> getAll() {
        return List.copyOf(cache);
    }

    /** Most recent N alerts from cache. */
    public List<AlertDto> getRecent(int n) {
        List<AlertDto> all = getAll();
        return all.subList(0, Math.min(n, all.size()));
    }

    /** Total persisted alert count (from DB — accurate across restarts). */
    public long size() {
        return repository.count();
    }
}

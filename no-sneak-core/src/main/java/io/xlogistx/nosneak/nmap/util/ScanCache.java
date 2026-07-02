package io.xlogistx.nosneak.nmap.util;

import org.zoxweb.shared.util.MapID;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Central registry of all maps used across the scan pipeline.
 * Each consumer calls {@link #newMap(String)} to get a tracked ConcurrentHashMap.
 * A single call to {@link #reset()} clears every registered map.
 */
public class ScanCache {

    private final Map<String, MapID> trackedMaps = new ConcurrentHashMap<>();

    /**
     * Create a new ConcurrentHashMap tracked by this cache under the given ID.
     *
     * @param id unique identifier for this map (e.g. "arp-cache", "tcp-pending")
     * @return a ConcurrentHashMap whose lifetime is managed by this cache
     */
    @SuppressWarnings("unchecked")
    public <K, V> Map<K, V> newMap(String id) {
        ConcurrentHashMap<K, V> map = new ConcurrentHashMap<>();
        trackedMaps.put(id, new MapID(id, map));
        return map;
    }

    /**
     * Look up a tracked map by ID.
     *
     * @param id the map identifier
     * @return the map, or null if not registered
     */
    @SuppressWarnings("unchecked")
    public <K, V> Map<K, V> getMap(String id) {
        MapID mapID = trackedMaps.get(id);
        return mapID != null ? (ConcurrentHashMap<K, V>) mapID.getValue() : null;
    }

    /**
     * Clear every tracked map in one shot.
     */
    public void reset() {
        for (MapID mapID : trackedMaps.values()) {
            mapID.getValue().clear();
        }
    }

    /**
     * Number of maps tracked by this cache.
     */
    public int mapCount() {
        return trackedMaps.size();
    }
}

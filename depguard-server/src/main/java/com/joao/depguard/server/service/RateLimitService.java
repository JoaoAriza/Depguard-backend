package com.joao.depguard.server.service;

import com.joao.depguard.server.model.AppUser;
import com.joao.depguard.server.model.Role;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Fork do {@code RateLimitService} do CyberAudit, adaptado pro {@link Role}
 * simplificado do DepGuard (OWNER/ADMIN/MEMBER — sem FREE_EMPLOYEE/plano).
 */
@Service
public class RateLimitService {

    public static final int GUEST_RPM = 20;
    public static final int MEMBER_RPM = 60;
    public static final int ADMIN_RPM = 120;

    private final ConcurrentMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public boolean allow(String ip, AppUser currentUser) {
        if (currentUser != null && currentUser.getRole() == Role.OWNER) {
            return true; // OWNER sem limite, mesmo critério do CyberAudit
        }

        int rpm = resolveRpm(currentUser);
        Bucket bucket = buckets.computeIfAbsent(buildKey(ip, currentUser), k -> buildBucket(rpm));
        return bucket.tryConsume(1);
    }

    private int resolveRpm(AppUser user) {
        if (user == null) {
            return GUEST_RPM;
        }
        return switch (user.getRole()) {
            case ADMIN -> ADMIN_RPM;
            case MEMBER -> MEMBER_RPM;
            case OWNER -> Integer.MAX_VALUE; // inalcançável: OWNER já retorna acima
        };
    }

    private String buildKey(String ip, AppUser user) {
        return user != null ? "user:" + user.getId() : "ip:" + ip;
    }

    private Bucket buildBucket(int rpm) {
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(rpm)
                        .refillGreedy(rpm, Duration.ofMinutes(1))
                        .build())
                .build();
    }
}

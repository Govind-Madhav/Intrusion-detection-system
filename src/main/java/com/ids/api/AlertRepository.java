package com.ids.api;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Spring Data JPA repository for persisted alerts.
 * All query methods are auto-implemented by Spring at runtime.
 */
@Repository
public interface AlertRepository extends JpaRepository<AlertEntity, String> {

    /** All alerts for a given type, newest first. */
    List<AlertEntity> findByAlertTypeIgnoreCaseOrderByTimestampDesc(String alertType);

    /** All alerts for a given severity, newest first. */
    List<AlertEntity> findBySeverityIgnoreCaseOrderByTimestampDesc(String severity);

    /** Filtered page: type + severity (both optional via JPQL). */
    @Query("SELECT a FROM AlertEntity a " +
           "WHERE (:type IS NULL OR LOWER(a.alertType) = LOWER(:type)) " +
           "AND   (:severity IS NULL OR LOWER(a.severity) = LOWER(:severity)) " +
           "ORDER BY a.timestamp DESC")
    Page<AlertEntity> findFiltered(String type, String severity, Pageable pageable);

    /** Count by alert type — used by /api/stats. */
    long countByAlertTypeIgnoreCase(String alertType);

    /** Count by severity — used by /api/stats. */
    long countBySeverityIgnoreCase(String severity);
}

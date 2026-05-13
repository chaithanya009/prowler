WITH rule_params AS (
    SELECT
        %s::uuid AS tenant_id,
        %s::uuid AS provider_id,
        NOW() - MAKE_INTERVAL(mins => %s::int) AS window_start
),
office_home AS (
    SELECT DISTINCT ON (event.session_id)
        event.id,
        event.session_id,
        event.timestamp,
        event.ip_address,
        event.location->>'countryOrRegion' AS country
    FROM secto_m365_signin_logs AS event
    JOIN rule_params AS params
        ON event.tenant_id = params.tenant_id
        AND event.provider_id = params.provider_id
    WHERE event.timestamp >= params.window_start
        AND event.client_app_used = 'Browser'
        AND event.session_id <> ''
        AND event.app_id = '4765445b-32c6-49b0-83e6-1d93765276ca'
        AND event.is_interactive = true
        AND event.status->>'errorCode' = '0'
        AND COALESCE(event.location->>'countryOrRegion', '') <> ''
    ORDER BY event.session_id, event.timestamp
),
suspicious_events AS (
    SELECT
        event.id,
        event.session_id,
        event.timestamp,
        event.app_display_name,
        event.ip_address,
        event.user_id,
        event.user_principal_name,
        event.location->>'countryOrRegion' AS country,
        office_home.id AS office_home_event_id,
        office_home.timestamp AS office_home_timestamp,
        office_home.ip_address AS office_home_ip,
        office_home.country AS office_home_country
    FROM secto_m365_signin_logs AS event
    JOIN office_home
        ON event.session_id = office_home.session_id
    JOIN rule_params AS params
        ON event.tenant_id = params.tenant_id
        AND event.provider_id = params.provider_id
    WHERE event.timestamp > office_home.timestamp
        AND event.client_app_used = 'Browser'
        AND event.app_id <> '4765445b-32c6-49b0-83e6-1d93765276ca'
        AND COALESCE(event.location->>'countryOrRegion', '') <> ''
        AND event.location->>'countryOrRegion' <> office_home.country
),
session_threats AS (
    SELECT
        session_id AS alert_key,
        MIN(office_home_timestamp) AS first_seen,
        MAX(timestamp) AS last_seen,
        ARRAY_REMOVE(ARRAY_AGG(DISTINCT COALESCE(user_principal_name, user_id)), '') AS affected_users,
        ARRAY_REMOVE(ARRAY_AGG(DISTINCT HOST(ip_address)), NULL) AS source_ip_addresses,
        ARRAY_REMOVE(ARRAY_AGG(DISTINCT country), '') AS countries,
        COUNT(*) + 1 AS related_events_count,
        JSONB_BUILD_OBJECT(
            'origin_country', MIN(office_home_country),
            'origin_ip', MIN(HOST(office_home_ip)),
            'applications', ARRAY_REMOVE(ARRAY_AGG(DISTINCT app_display_name), ''),
            'event_ids', ARRAY_PREPEND(
                MIN(office_home_event_id::text),
                ARRAY_AGG(id::text ORDER BY timestamp)
            )
        ) AS evidence
    FROM suspicious_events
    GROUP BY session_id
)
SELECT *
FROM session_threats
ORDER BY last_seen;

ALTER TABLE daily_checkins
    DROP CONSTRAINT daily_checkins_assignment_id_day_number_key,
    ADD CONSTRAINT daily_checkins_assignment_day_unique UNIQUE (assignment_id, day_number);

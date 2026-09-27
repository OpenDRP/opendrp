
class TestCeleryWiring:
    def test_celery_discovers_only_core_owned_task_modules(self):
        from app.core.celery_app import celery_app

        includes = celery_app.conf["include"]
        assert "app.tasks.report_tasks" in includes
        assert "app.tasks.scheduler_tasks" in includes
        assert "app.tasks.retention_tasks" in includes
        assert "app.tasks.phishing_tasks" not in includes
        assert "app.tasks.hibp_tasks" not in includes

    def test_routes_exclude_legacy_provider_tasks(self):
        from app.core.celery_app import celery_app

        tasks = celery_app.conf.task_routes
        assert "generate_report" in tasks
        assert tasks["generate_report"]["queue"] == "reports"
        assert "refresh_scan_schedules" in tasks
        assert "purge_expired_data" in tasks
        for legacy in ("scan_dnstwist", "shodan_brand_hunting", "hibp_daily_scan"):
            assert legacy not in tasks

    def test_every_scheduled_task_is_one_the_app_registers(self):
        """A beat entry that names a task nothing registers never fires.

        `celery-beat` can be perfectly healthy while a schedule in this dict does
        nothing at all: the entry is just a string until a worker resolves it, so
        a renamed, removed or misspelled task stops its work silently — which is
        how the alert-delivery tick and three maintenance jobs were lost. `include`
        is only a list until the loader imports it, so the first assertion below
        is the same import the worker performs at startup.
        """
        from app.core.celery_app import celery_app

        celery_app.loader.import_default_modules()
        registered = set(celery_app.tasks)
        scheduled = {
            entry_name: entry["task"]
            for entry_name, entry in celery_app.conf.beat_schedule.items()
        }

        assert scheduled
        assert {
            entry: task for entry, task in scheduled.items() if task not in registered
        } == {}

    def test_beat_schedule_runs_dynamic_scheduler_tick(self):
        """Scans are scheduled dynamically from system_settings; beat only runs
        the every-minute tick that reads them."""
        from app.core.celery_app import celery_app

        sched = celery_app.conf.beat_schedule
        names = [e["task"] for e in sched.values()]
        assert "refresh_scan_schedules" in names

    def test_beat_schedule_sweeps_expired_data_once_a_day(self):
        """Retention must run on a wall-clock slot that is not a scan slot.

        The default scan schedules are 02:30 and 03:30 UTC; a sweep that shared
        either slot would compete with the work it is trimming, and the reports
        that generate at those times must not become deletion candidates in the
        same night.
        """
        from app.core.celery_app import celery_app

        entry = celery_app.conf.beat_schedule["purge-expired-data-daily"]
        assert entry["task"] == "purge_expired_data"
        schedule = entry["schedule"]

        def _cron_values(value):
            # Celery keeps a cronspec field as a set of ints (expanded) or as a
            # plain int, depending on how it was given; accept both so the
            # assertion is about the slot, not about Celery's internals.
            if isinstance(value, (set, frozenset, list, tuple)):
                return {int(v) for v in value}
            return {int(value)}

        # A crontab object, so the slot is a fixed wall-clock time rather than
        # an interval that drifts with each beat restart.
        assert _cron_values(schedule.hour) == {4}
        assert _cron_values(schedule.minute) == {15}

    def test_beat_schedule_verifies_the_audit_chain_once_a_day(self):
        """The chain check is a scheduled task, not something an operator remembers.

        Its slot must not collide with the retention sweep at 04:15 either: the
        sweep is what *removes* rows, and a verification that ran alongside it
        could report a gap the purge itself created.
        """
        from app.core.celery_app import celery_app

        entry = celery_app.conf.beat_schedule["verify-audit-chain-daily"]
        assert entry["task"] == "verify_audit_chain"

        def _cron_values(value):
            if isinstance(value, (set, frozenset, list, tuple)):
                return {int(v) for v in value}
            return {int(value)}

        schedule = entry["schedule"]
        assert (_cron_values(schedule.hour), _cron_values(schedule.minute)) != (4, 15)

    def test_only_core_tasks_are_exported(self):
        from app import tasks

        assert tasks.__all__ == [
            "generate_report_task",
            "purge_expired_data_task",
            "refresh_scan_schedules_task",
            "verify_audit_chain_task",
        ]
        assert callable(tasks.generate_report_task)
        assert callable(tasks.purge_expired_data_task)
        assert callable(tasks.refresh_scan_schedules_task)
        assert callable(tasks.verify_audit_chain_task)

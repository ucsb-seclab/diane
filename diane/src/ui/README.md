## HOWTO

* Use RERAN

```python
from ui import install_reran, record_ui, replay_ui, translate_events_log

# First - Install
install_reran()

# Second - Record
events_log_path = 'data/example.log'
record_ui(events_log_path)

# Third - Translate
translate_events_log(events_log_path)

# Fourth - Replay
replay_ui()

```

* Use Monkey

```python
from ui import start_monkey

start_monkey(package='org.package.example',
			 seed='31337',
			 throttle='2000',
             pct_syskeys='0',
             pct_anyevent='0',
             ignore_crashes=True,
             ignore_timeouts=True,
             ignore_security_exceptions=False,
             num_events='500')

```

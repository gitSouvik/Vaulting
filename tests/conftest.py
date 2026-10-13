from hypothesis import HealthCheck, settings

# Globally register and activate no-deadline profiles for CI / testing
settings.register_profile(
    "default",
    deadline=None,
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.function_scoped_fixture,
    ],
)
settings.register_profile(
    "ci",
    deadline=None,
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.function_scoped_fixture,
    ],
)
settings.load_profile("ci")

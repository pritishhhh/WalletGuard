from teaching.evidence import detect


def test_teaching_fixture_detection():
    assert len(detect()['findings']) == 3

import time
import timeit

import aqgaming


def aqgaming_clientRegister():
    print("aqgaming_clientRegister >>>")
    aqgaming.clientRegister()
    time.sleep(3)
    aqgaming.kickLib()
    time.sleep(3)
    print("<<< aqgaming_clientRegister")


def aqgaming_clientUnregister():
    print("aqgaming_clientUnregister >>>")
    aqgaming.clientUnregister()
    time.sleep(3)
    print("<<< aqgaming_clientUnregister")


def aqgaming_poll_activated(active):
    start_time = timeit.default_timer()
    while timeit.default_timer() - start_time < 10.0:
        aqgaming.kickLib()
        requested_state = aqgaming.getParameter(aqgaming.AQCOMM_SERVER_REQUESTED_STATE)
        print("AQGaming requested state = {}".format(requested_state))
        if active and not requested_state:
            aqgaming.activate()
            continue
        elif not active and requested_state:
            aqgaming.deactivate()
            continue
        actual_state = aqgaming.getParameter(aqgaming.AQCOMM_SERVER_ACTUAL_STATE)
        print("AQGaming actual state = {}".format(actual_state))
        if (active and actual_state) or (not active and not actual_state):
            break
        time.sleep(1)
    else:
        return False

    return True


def aqgaming_activate(retry=True):
    print("aqgaming_activate >>>")
    aqgaming.activate()
    time.sleep(1)
    aqgaming.kickLib()
    time.sleep(1)

    assert aqgaming.getParameter(aqgaming.AQCOMM_SERVER_REQUESTED_STATE) == 1, \
        "Requested state parameter didn't set to 1"

    activated = aqgaming_poll_activated(active=True)
    if not activated and retry:
        print("AQGaming client wasn't activated. Cycling through deactivate-activate...")
        aqgaming.deactivate()
        aqgaming.kickLib()
        time.sleep(1)
        aqgaming.activate()
        aqgaming.kickLib()
        time.sleep(1)
        activated = aqgaming_poll_activated(active=True)

    if not activated:
        raise Exception("Failed to activate AQGaming client")
    print("<<< aqgaming_activate")


def aqgaming_deactivate(retry=True):
    print("aqgaming_deactivate >>>")
    aqgaming.deactivate()
    time.sleep(1)
    aqgaming.kickLib()
    time.sleep(1)

    assert aqgaming.getParameter(aqgaming.AQCOMM_SERVER_REQUESTED_STATE) == 0, \
        "Requested state parameter didn't set to 0"

    deactivated = aqgaming_poll_activated(active=False)
    if not deactivated and retry:
        print("AQGaming client wasn't activated. Cycling through activate-deactivate...")
        aqgaming.activate()
        aqgaming.kickLib()
        time.sleep(1)
        aqgaming.deactivate()
        aqgaming.kickLib()
        time.sleep(1)
        deactivated = aqgaming_poll_activated(active=False)

    if not deactivated:
        raise Exception("Failed to deactivate AQGaming client")
    print("<<< aqgaming_deactivate")


if __name__ == "__main__":
    for i in range(50):
        print("#" * 80)
        print("Iteration {}".format(i))
        print("#" * 80)

        aqgaming_clientRegister()

        aqgaming_activate(retry=False)

        for _ in range(10):
            aqgaming.kickLib()
            time.sleep(1)

        activated = aqgaming.getParameter(aqgaming.AQCOMM_SERVER_ACTUAL_STATE)
        assert activated, "AQGaming client is not activate after 10 seconds idling"

        print("Deactivating AQGaming client...")
        aqgaming_deactivate(retry=False)
        aqgaming.clientUnregister()
        time.sleep(3)

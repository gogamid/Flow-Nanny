import sched, time
s = sched.scheduler(time.time, time.sleep)
def do_something(sc, controller): 
    print("Resetting drop rate\n")
    # do your stuff
    s.enter(5, 1, do_something, (sc, controller))

s.enter(5, 1, do_something, (s, "controller"))
# s.run()
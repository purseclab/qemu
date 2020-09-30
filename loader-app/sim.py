#Import angr
import angr
#Make project
proj = angr.Project('/home/arslan/sgxsdk3/sgxsdk/SampleCode/SampleEnclave/app')
state = proj.factory.entry_state()
sm = proj.factory.simulation_manager(state)
while len(sm.active) == 1:
	proj.factory.block(sm.active[0].addr).pp()
	sm.step()



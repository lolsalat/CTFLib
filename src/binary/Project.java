package binary;

import java.io.IOException;

import ghidra.base.project.GhidraProject;
import ghidra.program.model.listing.Program;

public class Project {

	public Project(GhidraProject project) {
		this.project = project;
	}
	
	public GhidraProject project;
	
	public Program openProgram(String name) {
		try {
			return project.openProgram("/", name, false);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
}


find_program(PLANTUML plantuml)
if(DEFINED PLANTUML)
  message(STATUS "PLANTUML found! " ${PLANTUML})
  set(PlantUML ${PLANTUML})
  set(plantuml_FOUND 1) 
endif()

if(NOT DEFINED plantuml_FOUND)

  find_file(PLANTUML_JARFILE
    NAMES plantuml.jar
    HINTS "" ENV PLANTUML_DIR
  )

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(
  PlantUML DEFAULT_MSG PLANTUML_JARFILE)
 
  set(plantuml_FOUND 1) 

endif()
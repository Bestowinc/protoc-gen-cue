package v1

@protobuf(enums.v1,syntax=proto3)

#Color: *"COLOR_UNSPECIFIED" | =~"^(COLOR_RED|COLOR_GREEN|COLOR_BLUE)$" | error("invalid Color: want one of COLOR_UNSPECIFIED, COLOR_RED, COLOR_GREEN, COLOR_BLUE")

#Color_COLOR_UNSPECIFIED: "COLOR_UNSPECIFIED"

#Color_COLOR_RED: "COLOR_RED"

#Color_COLOR_GREEN: "COLOR_GREEN"

#Color_COLOR_BLUE: "COLOR_BLUE"

#Single: "SINGLE_ONLY"

#Single_SINGLE_ONLY: "SINGLE_ONLY"

#Pair: *"PAIR_ZERO" | "PAIR_ONE" | error("invalid Pair: want one of PAIR_ZERO, PAIR_ONE")

#Pair_PAIR_ZERO: "PAIR_ZERO"

#Pair_PAIR_ONE: "PAIR_ONE"

#Status: *"STATUS_UNSPECIFIED" | =~"^(STATUS_STARTED|STATUS_RUNNING|STATUS_DONE)$" | error("invalid Status: want one of STATUS_UNSPECIFIED, STATUS_STARTED, STATUS_RUNNING, STATUS_DONE")

#Status_STATUS_UNSPECIFIED: "STATUS_UNSPECIFIED"

#Status_STATUS_STARTED: "STATUS_STARTED"

#Status_STATUS_RUNNING: "STATUS_RUNNING"

#Status_STATUS_DONE: "STATUS_DONE"

#ZeroAlias: *"ZERO_ALIAS_FIRST" | =~"^(ZERO_ALIAS_SECOND|ZERO_ALIAS_ONE)$" | error("invalid ZeroAlias: want one of ZERO_ALIAS_FIRST, ZERO_ALIAS_SECOND, ZERO_ALIAS_ONE")

#ZeroAlias_ZERO_ALIAS_FIRST: "ZERO_ALIAS_FIRST"

#ZeroAlias_ZERO_ALIAS_SECOND: "ZERO_ALIAS_SECOND"

#ZeroAlias_ZERO_ALIAS_ONE: "ZERO_ALIAS_ONE"

#Paint_Finish: *"FINISH_UNSPECIFIED" | =~"^(FINISH_MATTE|FINISH_GLOSS)$" | error("invalid Paint_Finish: want one of FINISH_UNSPECIFIED, FINISH_MATTE, FINISH_GLOSS")

#Paint_FINISH_UNSPECIFIED: "FINISH_UNSPECIFIED"

#Paint_FINISH_MATTE: "FINISH_MATTE"

#Paint_FINISH_GLOSS: "FINISH_GLOSS"

#Paint: {
	@protobuf(enums.v1.Paint)
	color:  #Color        @go(Color) @protobuf(1,name=color)
	finish: #Paint_Finish @go(Finish) @protobuf(2,name=finish)
}

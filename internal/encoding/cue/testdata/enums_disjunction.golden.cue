package v1

@protobuf(enums.v1,syntax=proto3)

#Color: *#Color_COLOR_UNSPECIFIED | #Color_COLOR_RED | #Color_COLOR_GREEN | #Color_COLOR_BLUE

#Color_COLOR_UNSPECIFIED: "COLOR_UNSPECIFIED"

#Color_COLOR_RED: "COLOR_RED"

#Color_COLOR_GREEN: "COLOR_GREEN"

#Color_COLOR_BLUE: "COLOR_BLUE"

#Single: #Single_SINGLE_ONLY

#Single_SINGLE_ONLY: "SINGLE_ONLY"

#Pair: *#Pair_PAIR_ZERO | #Pair_PAIR_ONE

#Pair_PAIR_ZERO: "PAIR_ZERO"

#Pair_PAIR_ONE: "PAIR_ONE"

#Status: *#Status_STATUS_UNSPECIFIED | #Status_STATUS_STARTED | #Status_STATUS_RUNNING | #Status_STATUS_DONE

#Status_STATUS_UNSPECIFIED: "STATUS_UNSPECIFIED"

#Status_STATUS_STARTED: "STATUS_STARTED"

#Status_STATUS_RUNNING: "STATUS_RUNNING"

#Status_STATUS_DONE: "STATUS_DONE"

#ZeroAlias: *#ZeroAlias_ZERO_ALIAS_FIRST | *#ZeroAlias_ZERO_ALIAS_SECOND | #ZeroAlias_ZERO_ALIAS_ONE

#ZeroAlias_ZERO_ALIAS_FIRST: "ZERO_ALIAS_FIRST"

#ZeroAlias_ZERO_ALIAS_SECOND: "ZERO_ALIAS_SECOND"

#ZeroAlias_ZERO_ALIAS_ONE: "ZERO_ALIAS_ONE"

#Paint_Finish: *#Paint_FINISH_UNSPECIFIED | #Paint_FINISH_MATTE | #Paint_FINISH_GLOSS

#Paint_FINISH_UNSPECIFIED: "FINISH_UNSPECIFIED"

#Paint_FINISH_MATTE: "FINISH_MATTE"

#Paint_FINISH_GLOSS: "FINISH_GLOSS"

#Paint: {
	@protobuf(enums.v1.Paint)
	color:  #Color        @go(Color) @protobuf(1,name=color)
	finish: #Paint_Finish @go(Finish) @protobuf(2,name=finish)
}

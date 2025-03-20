module RsaMount(
	input 			i_clk,
	input			i_rst,
	input	[255:0] y,
	input	[255:0] N,
);
//deal with y*2^256 mod(N)

endmodule

module RsaPrep(
	input			i_clk,
	input			i_rst,
	input			t_r,
	output			t_w,
);
//use Montgomery Algorithm

endmodule

module Rsa256Core (
	input          i_clk,
	input          i_rst,
	input          i_start,
	input  [255:0] i_a, // cipher text y
	input  [255:0] i_d, // private key
	input  [255:0] i_n,
	output [255:0] o_a_pow_d, // plain text x
	output         o_finished
);

// operations for RSA256 decryption
// namely, the Montgomery algorithm
parameter IDLE = 2'd0, PREP = 2'd1, MONT = 2'd2, CALC = 2'd3;

logic[1:0] state_w, state_r;
logic[7:0] counter_w, counter_r;
logic rsa_prep_done, rsa_mont_done;
logic [255:0] rsa_mont_out;

always_comb begin
	state_w = state_r;
	case(state_r)
		IDLE:begin
			if(i_start) begin
				state_w = PREP;
			end
		end
		PREP:begin
			if(rsa_prep_done) begin
				state_w = MONT;
			end
		end
		MONT:begin
			if(rsa_mont_done) begin
				state_w = CALC;
			end
		end
		CALC:begin
			if(counter_r != 8'd255) begin
				state_w = MONT;
			end
			else begin
				state_w = IDLE;
			end
		end
	endcase
end

always_ff@(posedge i_clk or posedge i_rst) begin
	if(i_rst)begin
		//reset condition
		state_r <= IDLE;
		counter_r <= 0;
	end
	else begin
		state_r <= state_w;
		counter_r <= counter_w;
	end
end

endmodule

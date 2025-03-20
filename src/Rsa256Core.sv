module RsaPrep(
	input 			i_clk,
	input			i_rst,
	input	[255:0] y,
	input	[255:0] N,
	output	[255:0]	t,
	output 			done,
);
//deal with y*2^256 mod (N)
logic [8:0] count_r, count_w;
logic [255:0] m_w, m_r, t_w, t_r;
logic [256:0] doublet;

assign doublet = {t_r, 1'b0};
assign t = m_r;
assign done = (count_r == 9'd257);

always_comb begin
	//default values
	m_w = m_r;
	t_w = t_r;
	//i = 0, 1, ..., 256, 257
	count_w = (count_r == 9'd257)? 9'd0 : count_r + 1;

	if(count_r == 9'd256) begin //256th bit of a is 1
		if({1'b0, m_r} + {1'b0, t_r} >= {1'b0, N})begin
			m_w = {1'b0, m_r} + {1'b0, t_r} - {1'b0, N};
		end
		else begin
			m_w = m_r + t_r;
		end
	end

	if(doublet >= {1'b0, N}) begin
		t_w = doublet - {1'b0, N};
	end
	else begin
		t_w = doublet;
	end
end

always_ff @ (posedge i_clk or posedge i_rst) begin
	if(i_rst)begin
		m_r <= 256'd0;
		t_r <= y;
		count_r <= 9'd0;
	end
	else begin
		m_r <= m_w;
		t_r <= t_w;
		count_r <= count_w;
	end
end

endmodule

module RsaMont(
	input			i_clk,
	input			i_rst,
	input	[7:0]	counter,
	input			t_r,
	input	[255:0] m_r,
	output			t_w,
	output	[255:0] m_w,

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
logic [255:0] rsa_mont_out, t;

RsaPrep inst0 (.i_clk(i_clk), .i_rst(i_rst), .y(i_a), .N(i_n), .t(t), .done(rsa_prep_done));

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

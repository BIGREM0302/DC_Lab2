module RsaPrep(
	input 			i_clk,
	input			i_rst,
	input	[255:0] y,
	input	[255:0] N,
	input	[1:0]	state,
	output	[255:0]	t,
	output 			done
);
// deal with y * 2 ^ 256 mod (N)
logic [8:0]   count_r, count_w;
logic [255:0] m_w, m_r, t_w, t_r;
logic [256:0] doublet;

assign doublet = {t_r, 1'b0};
assign t = m_r;
assign done = (count_r == 9'd257);

always_comb begin
	// default values
	m_w = m_r;
	t_w = t_r;
	count_w = count_r;

	if (state == 2'b10) begin
		count_w = (count_r == 9'd257) ? 9'd0 : count_r + 1;
		// i = 0, 1, ..., 256, 257

		if (count_r == 9'd256) begin // 256th bit of a is 1
			if ({1'b0, m_r} + {1'b0, t_r} >= {1'b0, N}) begin
				m_w = {1'b0, m_r} + {1'b0, t_r} - {1'b0, N};
			end
			else begin
				m_w = m_r + t_r;
			end
		end

		if (doublet >= {1'b0, N}) begin
			t_w = doublet - {1'b0, N};
		end
		else begin
			t_w = doublet;
		end
	end
end

always_ff @(posedge i_clk or posedge i_rst) begin
	if (i_rst) begin
		m_r     <= 256'd0;
		t_r     <= y;
		count_r <= 9'd0;
	end
	else begin
		m_r     <= m_w;
		t_r     <= t_w;
		count_r <= count_w;
	end
end

endmodule

module RsaMont(
	input          i_clk,
	input          i_rst,
	input          enable,
	input  [255:0] N,
	input  [255:0] t_r,
	input  [255:0] m,
	output         MontFinish,
	output [255:0] t_w
);
// use Montgomery Algorithm
logic [257:0]  sum_w, sum_r;  // for safety :) 257 bit
logic [7:0]    counter_w, counter_r;
logic          state_w, state_r;

parameter MAX = 8'b11111111;

assign MontFinish = (counter_r == MAX) ? 1'b1 : 1'b0;
assign t_w = (MontFinish) ? sum_w : t_r;

always_comb begin
	// default
	state_w = (enable) & state_r;
	counter_w = (~enable) & counter_r;
	sum_w = (~enable) & sum_r;

	if ((~state_r) && enable) begin
		counter_w = counter_r + 1;

		case (MontFinish & enable)
			0: begin
				if ((t_r[counter_r] == 1) && ( sum_r[0] != m[0])) begin
					sum_w = (sum_r + m + N) >> 1;
				end
				else if ((t_r[counter_r] == 1) && (sum_r[0] == m[0])) begin
					sum_w = (sum_r + m) >> 1 ;
				end
				else begin
					if (sum_r[0] == 0) begin
						sum_w = sum_r >> 1 ;
					end
					else begin
						sum_w = (sum_r + N) >> 1 ;
					end
				end

				end

			1: begin
				if ((t_r[counter_r] == 1) && (sum_r[0] != m[0])) begin
					if (((sum_r + m + N) >> 1) >= N) begin
						sum_w = (sum_r + m + N) >> 1 - N;
					end
					else begin
						sum_w = (sum_r + m + N) >> 1;
					end
				end
				else if ((t_r[counter_r] == 1) && (sum_r[0] == m[0])) begin
					if (((sum_r + m) >> 1) >= N) begin
						sum_w = (sum_r + m) >> 1 - N;
					end
					else begin
						sum_w = (sum_r + m) >> 1;
					end
				end
				else begin
					if (sum_r[0] == 0) begin
						if ((sum_r >> 1 >= N)) begin
							sum_w = sum_r >> 1 - N;
						end
						else begin
							sum_w = sum_r >> 1;
						end
					end
					else begin
						if (((sum_r + N) >> 1 >= N)) begin
							sum_w = (sum_r + N) >> 1 - N;
						end
						else begin
							sum_w = (sum_r + N) >> 1;
						end
					end
				end
			end
		endcase
	end
end

always_ff @(posedge i_clk or posedge i_rst or posedge MontFinish or posedge enable) begin
	if (i_rst or enable) begin
		// reset condition
		state_r   <= 0;
		sum_r     <= 0;
		counter_r <= 0;
	end
	else if (MontFinish) begin
		// reset condition
		state_r   <= 1;
		sum_r     <= sum_w;
		counter_r <= 0;
	end
	else begin
		state_r   <= state_w;
		sum_r     <= sum_w;
		counter_r <= counter_w;
	end
end

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

logic [1:0]   state_w, state_r;
logic [7:0]   counter_w, counter_r;
logic         rsa_prep_done, rsa_mont_done1, rsa_mont_done2;
logic [255:0] rsa_prep_out, rsa_mont_out1, rsa_mont_out2;
logic [255:0] t_r, t_w;
logic [255:0] m_r, m_w;

assign o_a_pow_d = m_r;

RsaPrep inst0 (
	.i_clk(i_clk),
	.i_rst(i_rst),
	.y(i_a),
	.N(i_n),
	.state(state_r),
	.t(rsa_prep_out),
	.done(rsa_prep_done)
);

RsaMont inst1 (
	.i_clk(i_clk),
	.i_rst(i_rst),
	.enable(state_r[1] & (!state_r[0])),
	.N(i_n),
	.t_r(t_r),
	.m(m_r),
	.MontFinish(rsa_mont_done1),
	.t_w(rsa_mont_out1)
);

RsaMont inst2 (
	.i_clk(i_clk),
	.i_rst(i_rst),
	.enable(state_r[1] & (!state_r[0])),
	.N(i_n),
	.t_r(t_r),
	.m(t_r),
	.MontFinish(rsa_mont_done2),
	.t_w(rsa_mont_out2)
);

always_comb begin
	counter_w = counter_r;
	state_w = state_r;
	t_w = t_r;
	m_w = m_r;

	case (state_r)
		IDLE: begin
			if (i_start) begin
				state_w = PREP;
			end
		end

		PREP: begin
			if (rsa_prep_done) begin
				state_w = MONT;
				t_w = rsa_prep_out;
				m_w = 256'd1;
				counter_w = 8'd0;
			end
		end

		MONT: begin
			if (rsa_mont_done1 && rsa_mont_done2) begin
				state_w = CALC;
				counter_w = counter_r + 1;
				if(i_d[counter_r] == 1)	begin
					m_w = rsa_mont_out1;
				end
				t_w = rsa_mont_out2;
			end
		end
		CALC: begin
			if (counter_r != 0) begin // counter_w want to go to 9'b1,0000,0000 but only 8 bit
				state_w = MONT;
			end
			else begin
				state_w = IDLE;
				o_finished = 1'b1;
			end
		end
	endcase
end

always_ff @(posedge i_clk or posedge i_rst) begin
	if (i_rst) begin
		// reset condition
		state_r   <= IDLE;
		counter_r <= 8'd0;
		t_r       <= 256'd0;
		m_r       <= 256'd1;
	end
	else begin
		state_r   <= state_w;
		counter_r <= counter_w;
		t_r       <= t_w;
		m_r       <= m_w;
	end
end

endmodule

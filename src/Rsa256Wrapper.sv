module Rsa256Wrapper (
    input         avm_rst,
    input         avm_clk,
    output  [4:0] avm_address,
    output        avm_read,
    input  [31:0] avm_readdata,
    output        avm_write,
    output [31:0] avm_writedata,
    input         avm_waitrequest
);

localparam RX_BASE     = 0*4;
localparam TX_BASE     = 1*4;
localparam STATUS_BASE = 2*4;
localparam TX_OK_BIT   = 6;
localparam RX_OK_BIT   = 7;

// Feel free to design your own FSM!
localparam S_GET_KEY = 0;
localparam S_GET_DATA = 1;
localparam S_WAIT_CALCULATE = 2;
localparam S_SEND_DATA = 3;

logic [255:0] n_r, n_w, d_r, d_w, enc_r, enc_w, dec_r, dec_w;
logic [1:0] state_r, state_w;
logic [6:0] bytes_counter_r, bytes_counter_w;
logic [4:0] avm_address_r, avm_address_w;
logic avm_read_r, avm_read_w, avm_write_r, avm_write_w;

logic rsa_start_r, rsa_start_w;
logic rsa_finished;
logic [255:0] rsa_dec;
logic [27:0] counter_stop_r, counter_stop_w;

assign avm_address = avm_address_r;
assign avm_read = avm_read_r;
assign avm_write = avm_write_r;
assign avm_writedata = dec_r[247-:8];

Rsa256Core rsa256_core(
    .i_clk(avm_clk),
    .i_rst(avm_rst),
    .i_start(rsa_start_r),
    .i_a(enc_r),
    .i_d(d_r),
    .i_n(n_r),
    .o_a_pow_d(rsa_dec),
    .o_finished(rsa_finished)
);

task StartRead;
    input [4:0] addr;
    begin
        avm_read_w = 1;
        avm_write_w = 0;
        avm_address_w = addr;
    end
endtask

task StartWrite;
    input [4:0] addr;
    begin
        avm_read_w = 0;
        avm_write_w = 1;
        avm_address_w = addr;
    end
endtask

always_comb begin
    // TODO

    //default
    n_w             = n_r;
    d_w             = d_r;
    enc_w           = enc_r;
    dec_w           = dec_r;
    avm_address_w   = avm_address_r;
    avm_read_w      = avm_read_r;
    avm_write_w     = avm_write_r;
    state_w         = state_r;
    bytes_counter_w = bytes_counter_r;
    rsa_start_w     = rsa_start_r;
    counter_stop_w  = counter_stop_r;

    
    case(state_r)
        S_GET_KEY:begin
            if( avm_waitrequest == 0 ) begin

                if ( avm_address_r == STATUS_BASE ) begin
                    if(avm_readdata[RX_OK_BIT]==1)begin
                        StartRead(RX_BASE);
                        bytes_counter_w = bytes_counter_r + 1;
                    end
                end
                else if(avm_address_r == RX_BASE && avm_read_r == 1) begin
                    avm_address_w = STATUS_BASE;
                    if(bytes_counter_r <= 7'd95 ) begin
                        n_w = ((n_r<<8) | avm_readdata[7:0]);  
                    end

                    else if (bytes_counter_r == 7'd127) begin
                        d_w = ((d_r<<8) | avm_readdata[7:0]);
                        state_w = S_GET_DATA;
                    end

                    else begin
                        d_w = ((d_r<<8) | avm_readdata[7:0]);
                    end
                end
            end
        end

        S_GET_DATA:begin
            if( avm_waitrequest == 0 ) begin
                if (avm_address_r == STATUS_BASE) begin
                    if(avm_readdata[RX_OK_BIT]==1)begin
                        StartRead(RX_BASE);
                        bytes_counter_w = bytes_counter_r + 1;
                    end
                end
                else if(avm_address_r == RX_BASE && avm_read_r == 1) begin
                    avm_address_w = STATUS_BASE;
                    enc_w = ((enc_r<<8) | avm_readdata[7:0]); 
                    if(bytes_counter_r == 7'd31) begin
                        state_w = S_WAIT_CALCULATE;
                        rsa_start_w = 1;
                    end
                end
            end
            else begin
                counter_stop_w = counter_stop_r + 1;
                if(counter_stop_r == 28'b00111111111111111111111111111) begin
                    n_w = 0;
                    d_w = 0;
                    enc_w = 0;
                    dec_w = 0;
                    avm_address_w = STATUS_BASE;
                    avm_read_w = 1;
                    avm_write_w = 0;
                    state_w = S_GET_KEY;
                    bytes_counter_w = 63;
                    rsa_start_w = 0;
                    counter_stop_w = 0;
                end
            end
        end

        S_WAIT_CALCULATE:begin
            if(rsa_finished) begin
                state_w = S_SEND_DATA;
                dec_w = rsa_dec;
                rsa_start_w = 0;
            end
        end
        
        S_SEND_DATA:begin
            if( avm_waitrequest == 0 ) begin
                if (avm_address_r == STATUS_BASE) begin
                    if(avm_readdata[TX_OK_BIT]==1) begin
                        StartWrite(TX_BASE);
                        bytes_counter_w = bytes_counter_r + 1;
                    end
                end
                else if(avm_address_r == TX_BASE && avm_write_r == 1) begin
                    dec_w = dec_r << 8;
                    avm_address_w = STATUS_BASE;
                    avm_read_w = 1;
                    avm_write_w = 0;
                    if(bytes_counter_r == 7'd62) begin
                        state_w = S_GET_DATA;
                        enc_w = 0;
                        dec_w = 0;
                        avm_read_w = 1;
                        avm_write_w = 0;
                        bytes_counter_w = 7'd127;
                    end
                end
            end
        end
    endcase
end

always_ff @(posedge avm_clk or posedge avm_rst) begin
    if (avm_rst) begin
        n_r <= 0;
        d_r <= 0;
        enc_r <= 0;
        dec_r <= 0;
        avm_address_r <= STATUS_BASE;
        avm_read_r <= 1;
        avm_write_r <= 0;
        state_r <= S_GET_KEY;
        bytes_counter_r <= 63;
        rsa_start_r <= 0;
        counter_stop_r <= 0;
    end else begin
        n_r <= n_w;
        d_r <= d_w;
        enc_r <= enc_w;
        dec_r <= dec_w;
        avm_address_r <= avm_address_w;
        avm_read_r <= avm_read_w;
        avm_write_r <= avm_write_w;
        state_r <= state_w;
        bytes_counter_r <= bytes_counter_w;
        rsa_start_r <= rsa_start_w;
        counter_stop_r <= counter_stop_w;
    end
end

endmodule

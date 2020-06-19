----------------------------------------------------------------------
-- Company: SAL-Virginia Tech
-- Engineer: Behnaz Rezvani
-- 
-- Create Date: 02/05/2020
-- Module Name: GIFTCOFB_Datapath - Behavioral
-- Tool Versions: Vivado 2019.1
-- Description: Version 1
-- 
----------------------------------------------------------------------
library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.STD_LOGIC_UNSIGNED.ALL;
use work.SomeFunc.all;

-- Entity
----------------------------------------------------------------------
entity GIFTCOFB_Datapath is
  Port (
    clk, rst        : in  std_logic;
    GIFT_start      : in  std_logic;
    GIFT_done       : out std_logic;
    X_in_mux_sel    : in  std_logic;
    key, bdi        : in  std_logic_vector(31 downto 0);
    bdi_size        : in  std_logic_vector(2  downto 0);
    bdi_eot         : in  std_logic;
    bdo             : out std_logic_vector(31 downto 0);
    msg_auth        : out std_logic;
    ctr_words       : in  std_logic_vector(2  downto 0);
    ctr_bytes       : in  std_logic_vector(4  downto 0);
    KeyReg128_rst   : in  std_logic;
    KeyReg128_en    : in  std_logic;
    DstateReg_rst   : in  std_logic;
    DstateReg_en    : in  std_logic;
    Dstate_mux_sel  : in  std_logic_vector(1  downto 0);
    iDataReg_rst    : in  std_logic;
    iDataReg_en     : in  std_logic;
    iData_mux_sel   : in  std_logic_vector(1  downto 0);
    bdo_t_mux_sel   : in  std_logic
  );
end GIFTCOFB_Datapath;

-- Architecture
----------------------------------------------------------------------
architecture Behavioral of GIFTCOFB_Datapath is

    -- Constants ----------------------------------------------------
    constant zero64         : std_logic_vector(63  downto 0) := (others => '0');
    constant zero127        : std_logic_vector(126 downto 0) := (others => '0');

    -- Signals -------------------------------------------------------
    signal X_in             : std_logic_vector(127 downto 0);
    signal Y_out            : std_logic_vector(127 downto 0);
    
    signal KeyReg128_in     : std_logic_vector(127 downto 0);
    signal Key128_reg       : std_logic_vector(127 downto 0);
    signal DstateReg_in     : std_logic_vector(63  downto 0);
    signal DstateReg_out    : std_logic_vector(63  downto 0); -- Delta state
    signal iDataReg_in      : std_logic_vector(127 downto 0);
    signal iDataReg_out     : std_logic_vector(127 downto 0);
    signal Y_out_32         : std_logic_vector(31  downto 0);
    signal bdo_t            : std_logic_vector(31  downto 0);
    
----------------------------------------------------------------------    
begin
   
   -- GIFT Cipher
    Ek: entity work.GIFT128 -- GIFT Cipher
    Port map(
        clk     => clk,
        rst     => rst,
        start   => GIFT_start,
        Key     => Key128_reg,
        X_in    => X_in,
        Y_out   => Y_out,
        done    => GIFT_done
    );
    
    -- Registers
    
    KeyReg128_in <= Key128_reg(95 downto 0) & key;
    
    KeyReg128: entity work.myReg -- Register for 128-bit secret key
    generic map( b => 128)
    Port map(
        clk     => clk,
        rst     => KeyReg128_rst,
        en      => KeyReg128_en,
        D_in    => KeyReg128_in,
        D_out   => Key128_reg
    );
    
    DeltaReg: entity work.myReg -- Register for 64-bit delta state
    generic map( b => 64)
    Port map(
        clk     => clk,
        rst     => DstateReg_rst,
        en      => DstateReg_en,
        D_in    => DstateReg_in,
        D_out   => DstateReg_out
    );
    
    iDataReg: entity work.myReg -- Register for inputs: nonce, AD, PT/CT, expected tag
    generic map( b => 128)
    Port map(
        clk     => clk,
        rst     => iDataReg_rst,
        en      => iDataReg_en,
        D_in    => iDataReg_in,
        D_out   => iDataReg_out
    );

    -- Multiplexers
    
    with X_in_mux_sel select
        X_in <=  iDataReg_out                                                                         when '0',    -- Nonce
                 rho1(Y_out, Pad(iDataReg_out, conv_integer(ctr_bytes))) xor (DstateReg_out & zero64) when others; -- AD or PT

    with Dstate_mux_sel select
        DstateReg_in <=  Y_out(127 downto 64)    when "00",   -- Tranc(Ek(N))
                         Tripling(DstateReg_out) when "01",   -- 3*L
                         Doubling(DstateReg_out) when others; -- 2*L

    with iData_mux_sel select
        iDataReg_in <=  iDataReg_out(95 downto 0) & bdi                              when "00",   -- Nonce or expected tag
                        myMux(iDataReg_out(95 downto 0) & bdo_t, ctr_words, bdi_eot) when "10",   -- PT during the decryption                 
                        myMux(iDataReg_out(95 downto 0) & bdi,   ctr_words, bdi_eot) when others; -- AD or PT
                            
    Y_out_32 <=  Y_out((127 - conv_integer(ctr_words)*32) downto (96 - conv_integer(ctr_words)*32)); 

    with bdo_t_mux_sel select                      
        bdo_t <=  Y_out_32 xor bdi when '0',    -- CT(PT) =  Y xor PT(CT) 
                  Y_out_32         when others; -- Computed tag

    bdo <= bdo_t;
    
    msg_auth <=  '1' when (iDataReg_out = Y_out) else '0';

end Behavioral;

/*
 * Syntax Guide: https://docs.rs/caith/latest/caith/#syntax
 * Examples: https://docs.rs/caith/latest/caith/#examples
 *
 * Args:
 * * input: the xdy dice to roll; see syntax guide & examples for proper formatting.
 *
 * Returns:
 * * the total sum of the roll.
 */
#define rustg_roll_dice(input) text2num(RUSTG_CALL(RUST_G, "roll_dice")("[input]"))
